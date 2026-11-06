//go:build darwin || linux || windows

package hostdata

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestStrictXattrListInputs(t *testing.T) {
	for _, limit := range []int{-1, MaxXattrListSize + 1, 0} {
		if names, err := ListXattrNames(nil, limit); names != nil || !errors.Is(err, os.ErrInvalid) {
			t.Fatal(names, err)
		}
	}
	f, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if names, err := ListXattrNames(f, 1); names != nil || err == nil {
		t.Fatal(names, err)
	}
}

func TestStrictXattrListProtocol(t *testing.T) {
	for _, c := range []struct {
		name                     string
		data                     string
		size, read, limit, calls int
		first, second, want      error
	}{
		{"empty", "", 0, 0, 0, 2, nil, nil, nil},
		{"names", "z\x00a\x00", 4, 4, 4, 2, nil, nil, nil},
		{"negative", "", -1, 0, 0, 1, nil, nil, ErrXattrChanged},
		{"budget", "", 5, 0, 4, 1, nil, nil, ErrXattrTooLarge},
		{"query", "", 0, 0, 0, 1, os.ErrPermission, nil, os.ErrPermission},
		{"read", "", 4, 0, 4, 2, nil, os.ErrPermission, os.ErrPermission},
		{"grow", "", 4, 5, 4, 2, nil, nil, ErrXattrChanged},
		{"shrink", "", 4, 3, 4, 2, nil, nil, ErrXattrChanged},
		{"empty-grow", "", 0, 1, 0, 2, nil, nil, ErrXattrChanged},
		{"negative-read", "", 4, -1, 4, 2, nil, nil, ErrXattrChanged},
		{"range", "", 4, 0, 4, 2, nil, strictListRangeError(), ErrXattrChanged},
		{"framing", "a\x00a\x00", 4, 4, 4, 2, nil, nil, ErrXattrListMalformed},
	} {
		t.Run(c.name, func(t *testing.T) {
			calls := 0
			got, err := readXattrNames(func(buf []byte) (int, error) {
				calls++
				if calls == 1 {
					if buf != nil {
						t.Fatal("size query allocated")
					}
					return c.size, c.first
				}
				if len(buf) != max(c.size, 1) {
					t.Fatal("allocation", len(buf))
				}
				copy(buf, c.data)
				return c.read, c.second
			}, c.limit)
			if calls != c.calls || !errors.Is(err, c.want) {
				t.Fatal(calls, got, err)
			}
			if c.want != nil && got != nil {
				t.Fatal("partial list", got)
			}
			if c.want == nil && (got == nil || func() string {
				if len(got) == 0 {
					return ""
				}
				return strings.Join(got, "\x00") + "\x00"
			}() != c.data) {
				t.Fatal(got)
			}
			if c.name == "range" && !errors.Is(err, c.second) {
				t.Fatal("lost native error", err)
			}
		})
	}
}

func TestStrictXattrListFraming(t *testing.T) {
	for _, b := range [][]byte{{0}, []byte("unterminated"), []byte("a\x00\x00"), []byte("a\x00a\x00"), []byte("a\x00late")} {
		if n, e := parseXattrNames(b); n != nil || !errors.Is(e, ErrXattrListMalformed) {
			t.Fatal(n, e)
		}
	}
	b := []byte("z\x00A\x00a\x00\xff\x00")
	names, e := parseXattrNames(b)
	if e != nil || !reflect.DeepEqual(names, []string{"z", "A", "a", "\xff"}) {
		t.Fatal(names, e)
	}
	clear(b)
	if names[0] != "z" {
		t.Fatal("aliased input")
	}
	if n, e := parseXattrNames(nil); e != nil || n == nil || len(n) != 0 {
		t.Fatal(n, e)
	}
}

func listEARecord(name string, value []byte) []byte {
	b := make([]byte, 9+len(name)+len(value))
	b[5] = byte(len(name))
	binary.LittleEndian.PutUint16(b[6:], uint16(len(value)))
	copy(b[8:], name)
	copy(b[9+len(name):], value)
	return b
}
func TestStrictXattrListEAFraming(t *testing.T) {
	base := listEARecord("name", []byte("value"))
	bad := [][]byte{nil, base[:8], base[:12], base[:len(base)-1], listEARecord("", nil), listEARecord("a\x00b", nil)}
	for _, off := range []int{0, 12} {
		b := bytes.Clone(base)
		b[off] = 1
		bad = append(bad, b)
	}
	for i, b := range bad {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if n, v, e := parseXattrEA(b); n != "" || v != nil || !errors.Is(e, ErrXattrListMalformed) {
				t.Fatal(n, v, e)
			}
		})
	}
	for _, v := range [][]byte{nil, []byte("v"), bytes.Repeat([]byte{7}, 65535)} {
		b := listEARecord("Name", v)
		n, got, e := parseXattrEA(b)
		if e != nil || n != "Name" || !bytes.Equal(got, v) {
			t.Fatal(n, len(got), e)
		}
		b[8] = 'x'
		if n != "Name" {
			t.Fatal("aliased name")
		}
	}
}
func TestStrictXattrListEAEnumeration(t *testing.T) {
	for _, c := range []struct {
		name           string
		records        [][]byte
		limit          int
		terminal, want error
	}{
		{"empty", nil, 0, io.EOF, nil},
		{"names", [][]byte{listEARecord("z", []byte{1}), listEARecord("Alpha", bytes.Repeat([]byte{7}, 60000)), listEARecord("\xff", nil)}, 10, io.EOF, nil},
		{"budget", [][]byte{listEARecord("a", nil)}, 1, io.EOF, ErrXattrTooLarge},
		{"late-budget", [][]byte{listEARecord("a", nil), listEARecord("b", nil)}, 3, io.EOF, ErrXattrTooLarge},
		{"duplicate", [][]byte{listEARecord("Name", nil), listEARecord("NAME", nil)}, 100, io.EOF, ErrXattrChanged},
		{"malformed", [][]byte{listEARecord("a", nil), {}}, 100, io.EOF, ErrXattrListMalformed},
		{"query-error", nil, 0, os.ErrPermission, os.ErrPermission},
		{"late-error", [][]byte{listEARecord("a", nil)}, 100, os.ErrPermission, os.ErrPermission},
	} {
		t.Run(c.name, func(t *testing.T) {
			calls := 0
			names, e := readXattrEAs(func(b []byte, restart bool) (int, error) {
				if restart != (calls == 0) || len(b) != strictWindowsEABufferSize {
					t.Fatal("protocol", calls, restart, len(b))
				}
				i := calls
				calls++
				if i == len(c.records) {
					return 0, c.terminal
				}
				copy(b, c.records[i])
				return len(c.records[i]), nil
			}, c.limit)
			if !errors.Is(e, c.want) || (e != nil && names != nil) {
				t.Fatal(names, e)
			}
			if e == nil {
				if names == nil || len(names) != len(c.records) {
					t.Fatal(names)
				}
				for i, b := range c.records {
					if names[i] != string(b[8:8+int(b[5])]) {
						t.Fatal("order/ownership", names)
					}
				}
				if calls != len(c.records)+1 {
					t.Fatal(calls)
				}
			}
		})
	}
	for _, n := range []int{-1, strictWindowsEABufferSize + 1} {
		if names, e := readXattrEAs(func([]byte, bool) (int, error) { return n, nil }, 100); names != nil || !errors.Is(e, ErrXattrListMalformed) {
			t.Fatal(names, e)
		}
	}
}

func FuzzXattrListNames(f *testing.F) {
	for _, b := range [][]byte{nil, []byte("z\x00a\x00"), []byte("a\x00a\x00"), {0xff, 0}, []byte("no terminator")} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		names, e := parseXattrNames(b)
		if e != nil {
			if names != nil {
				t.Fatal("partial")
			}
			return
		}
		var round []byte
		seen := map[string]bool{}
		for _, n := range names {
			if n == "" || strings.ContainsRune(n, 0) || seen[n] {
				t.Fatal(names)
			}
			seen[n] = true
			round = append(round, []byte(n)...)
			round = append(round, 0)
		}
		if !bytes.Equal(round, b) {
			t.Fatal("changed name bytes")
		}
	})
}
func FuzzXattrEARecord(f *testing.F) {
	f.Add([]byte{})
	f.Add(listEARecord("name", []byte{1, 2}))
	f.Add(listEARecord("\xff", nil))
	f.Fuzz(func(t *testing.T, b []byte) {
		name, value, e := parseXattrEA(b)
		if e != nil {
			if name != "" || value != nil {
				t.Fatal("partial")
			}
			return
		}
		if name == "" || strings.ContainsRune(name, 0) {
			t.Fatal("invalid name")
		}
		round := listEARecord(name, value)
		round[4] = b[4]
		if len(round) > len(b) || !bytes.Equal(round, b[:len(round)]) {
			t.Fatal("changed EA bytes")
		}
	})
}
