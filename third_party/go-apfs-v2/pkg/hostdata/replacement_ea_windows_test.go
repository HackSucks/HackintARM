package hostdata

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func replacementEARecord(name, value []byte, flags byte) []byte {
	b := make([]byte, 9+len(name)+len(value))
	b[4] = flags
	b[5] = byte(len(name))
	binary.LittleEndian.PutUint16(b[6:8], uint16(len(value)))
	copy(b[8:], name)
	copy(b[9+len(name):], value)
	return b
}

func TestReplacementWindowsEARecords(t *testing.T) {
	first := replacementEARecord([]byte{'A', 0xe9}, []byte{0, 1, 255}, 0x80)
	second := replacementEARecord(bytes.Repeat([]byte{'Z'}, 255), bytes.Repeat([]byte{0x42}, 65535), 0)
	t.Run("complete raw records and padding", func(t *testing.T) {
		records := [][]byte{append(append([]byte(nil), first...), 0, 0, 0), second}
		var actual [][]byte
		index := 0
		err := copyReplacementEARecords(t.Context(), func(out []byte, restart bool) (uintptr, bool, error) {
			if restart != (index == 0) {
				t.Fatalf("restart=%v index=%d", restart, index)
			}
			if index == len(records) {
				return 0, true, nil
			}
			n := copy(out, records[index])
			index++
			return uintptr(n), false, nil
		}, func(record []byte) error { actual = append(actual, append([]byte(nil), record...)); return nil })
		if err != nil || len(actual) != 2 || !bytes.Equal(actual[0], first) || !bytes.Equal(actual[1], second) {
			t.Fatalf("raw EA fidelity: count=%d %v", len(actual), err)
		}
	})
	fault := errors.New("native EA failure")
	for _, kind := range []string{"query", "write", "short", "oversized", "next offset", "empty name", "truncated value", "missing terminator", "cancel before query", "cancel after query", "cancel after write", "cancel terminal query"} {
		t.Run(kind, func(t *testing.T) {
			base, cancel := context.WithCancel(t.Context())
			defer cancel()
			record := append([]byte(nil), first...)
			writes := 0
			if kind == "cancel before query" {
				cancel()
			}
			err := copyReplacementEARecords(base, func(out []byte, restart bool) (uintptr, bool, error) {
				if !restart {
					if kind == "cancel terminal query" {
						cancel()
					}
					return 0, true, nil
				}
				switch kind {
				case "query":
					return 0, false, fault
				case "short":
					return 1, false, nil
				case "oversized":
					return uintptr(len(out)) + 1, false, nil
				case "next offset":
					binary.LittleEndian.PutUint32(record, 4)
				case "empty name":
					record[5] = 0
				case "truncated value":
					binary.LittleEndian.PutUint16(record[6:8], 65535)
				case "missing terminator":
					record[8+int(record[5])] = 1
				case "cancel after query":
					cancel()
				}
				return uintptr(copy(out, record)), false, nil
			}, func([]byte) error {
				writes++
				if kind == "cancel after write" {
					cancel()
				}
				if kind == "write" {
					return fault
				}
				return nil
			})
			if err == nil {
				t.Fatal("invalid or canceled EA transfer succeeded")
			}
			if (kind == "query" || kind == "write") && !errors.Is(err, fault) {
				t.Fatal(err)
			}
			if len(kind) >= 6 && kind[:6] == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if kind != "write" && kind != "cancel after write" && kind != "cancel terminal query" && writes != 0 {
				t.Fatal("invalid EA reached native writer")
			}
		})
	}
}

func replacementQueryRawEA(t *testing.T, file *os.File, name []byte) []byte {
	t.Helper()
	query := make([]byte, 6+len(name))
	query[4] = byte(len(name))
	copy(query[5:], name)
	buffer := make([]byte, 65536)
	var status windows.IO_STATUS_BLOCK
	if err := windows.NtQueryEaFile(windows.Handle(file.Fd()), &status, &buffer[0], uint32(len(buffer)), true, &query[0], uint32(len(query)), nil, true); err != nil {
		t.Fatal(err)
	}
	if status.Information > uintptr(len(buffer)) {
		t.Fatal("native EA query overflow")
	}
	return buffer[:status.Information]
}

func TestReplacementWindowsEACopyNative(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("encrypted-%v", encrypted), func(t *testing.T) {
			sourceName := filepath.Join(t.TempDir(), "source")
			if err := os.WriteFile(sourceName, []byte("data"), 0600); err != nil {
				t.Fatal(err)
			}
			if encrypted {
				replacementEncrypt(t, sourceName)
			}
			source, err := os.OpenFile(sourceName, os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			names := [][]byte{[]byte("FIRST"), {'N', 0xe9}}
			for i, name := range names {
				record := replacementEARecord(name, []byte{byte(i), 0, 255}, byte(i*0x80))
				if err = windows.NtSetEaFile(windows.Handle(source.Fd()), &windows.IO_STATUS_BLOCK{}, &record[0], uint32(len(record))); err != nil {
					t.Fatal(err)
				}
			}
			target, err := os.CreateTemp(t.TempDir(), "target")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			if err = copyReplacementEAs(t.Context(), source, target); err != nil {
				t.Fatal(err)
			}
			for _, name := range names {
				before, after := replacementQueryRawEA(t, source, name), replacementQueryRawEA(t, target, name)
				if !bytes.Equal(before, after) {
					t.Fatalf("native EA flags/name/value changed: %x %x", before, after)
				}
			}
			readOnly, err := os.Open(target.Name())
			if err != nil {
				t.Fatal(err)
			}
			defer readOnly.Close()
			if err = copyReplacementEAs(t.Context(), source, readOnly); !errors.Is(err, windows.STATUS_ACCESS_DENIED) {
				t.Fatalf("native EA write denial: %v", err)
			}
			if err = readOnly.Close(); err != nil {
				t.Fatal(err)
			}
			if err = copyReplacementEAs(t.Context(), source, readOnly); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("closed EA target: %v", err)
			}
			if err = copyReplacementEAs(t.Context(), readOnly, target); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("closed EA source: %v", err)
			}
			checkpoints := 0
			for stop := 0; stop <= checkpoints; stop++ {
				t.Run(fmt.Sprintf("checkpoint-%d", stop), func(t *testing.T) {
					base, cancel := context.WithCancel(t.Context())
					defer cancel()
					ctx := &replacementCheckpointContext{Context: base, cancel: cancel, stop: stop}
					output, e := os.CreateTemp(t.TempDir(), "partial")
					if e != nil {
						t.Fatal(e)
					}
					defer output.Close()
					e = copyReplacementEAs(ctx, source, output)
					if stop == 0 {
						if e != nil {
							t.Fatal(e)
						}
						checkpoints = ctx.calls
					} else if !errors.Is(e, context.Canceled) {
						t.Fatalf("checkpoint %d/%d: %v", stop, checkpoints, e)
					}
					if e = output.Close(); e != nil {
						t.Fatal(e)
					}
					if e = os.Remove(output.Name()); e != nil {
						t.Fatalf("EA transfer leaked target: %v", e)
					}
				})
			}
		})
	}
	empty, err := os.CreateTemp(t.TempDir(), "empty")
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Close()
	target, err := os.CreateTemp(t.TempDir(), "target")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err = copyReplacementEAs(t.Context(), empty, target); err != nil {
		t.Fatalf("no EA native completion: %v", err)
	}
}
