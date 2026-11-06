package hostdata

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/decmpfs"
)

type compressionForkFunctions struct {
	write       func([]byte, int64) (int, error)
	sync, close func() error
}

func (b compressionForkFunctions) WriteAt(p []byte, at int64) (int, error) { return b.write(p, at) }
func (b compressionForkFunctions) Sync() error                             { return b.sync() }
func (b compressionForkFunctions) Close() error                            { return b.close() }

type compressionStageFunc func([]byte, int64) (int, error)

func (f compressionStageFunc) ReadAt(p []byte, at int64) (int, error) { return f(p, at) }

func TestInstallCompressionForkNativeLifecycle(t *testing.T) {
	trials := compressionLifecycleTrials(t)
	compared := 0
	for index, c := range trials {
		var events []compressionLifecycleEvent
		for _, line := range strings.Split(strings.TrimSpace(c.Trace), "\n") {
			if line == "" {
				continue
			}
			var e compressionLifecycleEvent
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				t.Fatal(err)
			}
			if e.Fork {
				events = append(events, e)
			}
		}
		if len(events) == 0 {
			continue
		} // Native did not open the fork stage.
		compared++
		t.Run(fmt.Sprintf("%d/%s/%s/%s/%s", index, c.Filesystem, c.Scenario, c.Inline, c.Fault), func(t *testing.T) {
			controlScenario := "ordinary"
			if c.Scenario == "multi-block" {
				controlScenario = "multi-block"
			}
			var storage decmpfs.EncodedFile
			var staged []byte
			for _, ordinary := range trials {
				if ordinary.Filesystem == c.Filesystem && ordinary.Scenario == controlScenario && ordinary.Requested == c.Requested && ordinary.Inline == c.Inline && ordinary.Fault == "" {
					storage = decmpfs.EncodedFile{Attribute: ordinary.Attribute, ForkSize: int64(len(ordinary.Fork))}
					staged = ordinary.Fork
					break
				}
			}
			if storage.Attribute == nil {
				t.Fatal("missing independently captured complete storage")
			}
			initial := 0
			if c.Scenario == "fork" {
				initial = 11
			}
			at, ignored := 0, 0
			var installed []byte
			if c.Scenario == "fork" {
				installed = []byte("independent")
			}
			terminal := false
			call := func(operation string, offset int64) compressionLifecycleEvent {
				t.Helper()
				if at >= len(events) {
					t.Fatalf("extra operation %s", operation)
				}
				e := events[at]
				at++
				if e.Operation != operation || e.Argument != offset {
					t.Fatalf("native %+v; Go %s(%d)", e, operation, offset)
				}
				return e
			}
			b := compressionForkFunctions{
				write: func(p []byte, offset int64) (int, error) {
					e := call("pwrite", offset)
					if !bytes.Equal(p, staged[offset:offset+int64(len(p))]) {
						t.Fatal("frame bytes differ")
					}
					if e.Errno != 0 {
						terminal = true
						return 0, fmt.Errorf("native errno %d", e.Errno)
					}
					if e.Result < 0 || e.Result > int64(len(p)) {
						t.Fatalf("native frame length %d; Go %d", e.Result, len(p))
					}
					terminal = e.Result < int64(len(p))
					installed = append(installed, p[:e.Result]...)
					return int(e.Result), nil
				},
				sync: func() error {
					e := call("fsync", 0)
					if e.Errno != 0 {
						ignored++
						return fmt.Errorf("native errno %d", e.Errno)
					}
					return nil
				},
				close: func() error {
					e := call("close", 0)
					if e.Errno != 0 {
						ignored++
						return fmt.Errorf("native errno %d", e.Errno)
					}
					return nil
				},
			}
			r, e := InstallCompressionFork(t.Context(), storage, bytes.NewReader(staged), int64(initial), b)
			if (e != nil) != terminal || r.Complete == (terminal || r.Declined) || at != len(events) || len(r.Failures) != ignored {
				t.Fatal(r, e, at, len(events), terminal, ignored)
			}
			if !bytes.Equal(installed, c.Fork) {
				t.Fatal("partial native fork differs", len(installed), len(c.Fork))
			}
			if r.Declined != (initial > 0 && storage.ForkSize > 0) {
				t.Fatal(r)
			}
			if r.BytesWritten != int64(len(installed)-initial) {
				t.Fatal(r)
			}
		})
	}
	if compared != 501 {
		t.Fatal("incomplete native fork stage inventory", compared)
	}
}

func compressionStagedFixture(t *testing.T, kind uint32) (decmpfs.EncodedFile, []byte) {
	t.Helper()
	f, e := os.CreateTemp(t.TempDir(), "compression-stage-")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	plain := bytes.Repeat([]byte("abcd"), 32769)
	s, e := decmpfs.Encode(t.Context(), bytes.NewReader(plain), int64(len(plain)), f, decmpfs.EncodeOptions{Type: kind, ResourceForkOnly: true})
	if e != nil || s.Attribute == nil {
		t.Fatal(s, e)
	}
	data, e := os.ReadFile(f.Name())
	if e != nil {
		t.Fatal(e)
	}
	if len(data) != int(s.ForkSize) {
		t.Fatal("staging extent", len(data), s.ForkSize)
	}
	return s, data
}

func TestInstallCompressionForkMultiBlockAndFailures(t *testing.T) {
	sentinel := errors.New("injected I/O")
	for _, kind := range []uint32{4, 8, 10, 12, 14} {
		storage, stage := compressionStagedFixture(t, kind)
		for _, fault := range []string{"", "index-read", "block-read", "map-read", "read-with-data", "eof-with-data", "index-write", "block-write", "map-write", "short-write", "negative-write", "oversized-write", "short-read", "sync", "close", "cancel-before", "cancel-read", "cancel-write"} {
			if strings.HasPrefix(fault, "map-") && kind != 4 {
				continue
			} // Only zlib has a Resource Manager map.
			t.Run(fmt.Sprintf("%d/%s", kind, fault), func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if fault == "cancel-before" {
					cancel()
				}
				reads, writes, syncs, closes := 0, 0, 0, 0
				var output []byte
				source := compressionStageFunc(func(p []byte, at int64) (int, error) {
					reads++
					if fault == "index-read" && reads == 1 || fault == "block-read" && reads == 2 || fault == "map-read" && at == storage.ForkSize-50 {
						return 0, sentinel
					}
					n, e := bytes.NewReader(stage).ReadAt(p, at)
					if fault == "short-read" {
						return n - 1, nil
					}
					if fault == "read-with-data" {
						return n, sentinel
					}
					if fault == "eof-with-data" {
						return n, io.EOF
					}
					if fault == "cancel-read" {
						cancel()
					}
					return n, e
				})
				writer := compressionForkFunctions{write: func(p []byte, at int64) (int, error) {
					writes++
					if fault == "index-write" && writes == 1 || fault == "block-write" && writes == 2 || fault == "map-write" && at == storage.ForkSize-50 {
						return 0, sentinel
					}
					if fault == "short-write" {
						return len(p) - 1, nil
					}
					if fault == "negative-write" {
						return -1, sentinel
					}
					if fault == "oversized-write" {
						return len(p) + 1, sentinel
					}
					if at != int64(len(output)) {
						t.Fatal("non-sequential frame", at, len(output))
					}
					output = append(output, p...)
					if fault == "cancel-write" {
						cancel()
					}
					return len(p), nil
				}, sync: func() error {
					syncs++
					if fault == "sync" {
						return sentinel
					}
					return nil
				}, close: func() error {
					closes++
					if fault == "close" {
						return sentinel
					}
					return nil
				}}
				r, e := InstallCompressionFork(ctx, storage, source, 0, writer)
				success := fault == "" || fault == "sync" || fault == "close" || fault == "eof-with-data"
				if syncs != 1 || closes != 1 || (e == nil) != success || r.Complete != success {
					t.Fatal(r, e, reads, writes, syncs, closes)
				}
				if success && (!bytes.Equal(output, stage) || r.BytesWritten != storage.ForkSize) {
					t.Fatal("complete bytes differ", r)
				}
				if (fault == "sync" || fault == "close") && (len(r.Failures) != 1 || !errors.Is(r.Failures[0].Err, sentinel)) {
					t.Fatal(r)
				}
				if strings.HasPrefix(fault, "cancel-") && !errors.Is(e, context.Canceled) {
					t.Fatal(e)
				}
			})
		}
	}
}

func TestInstallCompressionForkInvalidStorage(t *testing.T) {
	storage, stage := compressionStagedFixture(t, 4)
	for _, fault := range []string{"nil-fork", "negative-size", "bad-attribute", "empty-logical", "large-logical", "unsupported-kind", "nil-stage", "short-fork", "bad-zlib-header", "bad-index-start", "bad-index-length", "bad-index-end", "inline-with-fork"} {
		t.Run(fault, func(t *testing.T) {
			s := decmpfs.EncodedFile{Attribute: bytes.Clone(storage.Attribute), ForkSize: storage.ForkSize}
			data := bytes.Clone(stage)
			var source io.ReaderAt = bytes.NewReader(data)
			closed := false
			var fork CompressionForkWriter = compressionForkFunctions{write: func([]byte, int64) (int, error) { t.Fatal("invalid storage mutated fork"); return 0, nil }, sync: func() error { return nil }, close: func() error { closed = true; return nil }}
			switch fault {
			case "nil-fork":
				fork = nil
			case "negative-size":
				s.ForkSize = -1
			case "bad-attribute":
				s.Attribute = nil
			case "empty-logical":
				binary.LittleEndian.PutUint64(s.Attribute[8:], 0)
			case "large-logical":
				binary.LittleEndian.PutUint64(s.Attribute[8:], 512<<20+1)
			case "unsupported-kind":
				binary.LittleEndian.PutUint32(s.Attribute[4:], 16)
			case "nil-stage":
				source = nil
			case "short-fork":
				s.ForkSize = 1
			case "bad-zlib-header":
				data[12] = 1
			case "bad-index-start":
				binary.LittleEndian.PutUint32(data[264:], 999)
			case "bad-index-length":
				binary.LittleEndian.PutUint32(data[268:], 65538)
			case "bad-index-end":
				n := binary.LittleEndian.Uint32(data[284:])
				binary.LittleEndian.PutUint32(data[284:], n-1)
			case "inline-with-fork":
				binary.LittleEndian.PutUint32(s.Attribute[4:], 3)
				s.Attribute = append(s.Attribute, 0xff)
			}
			if r, e := InstallCompressionFork(t.Context(), s, source, 0, fork); e == nil || r.Complete || closed != (fork != nil) {
				t.Fatal(r, e, closed)
			}
		})
	}
}
