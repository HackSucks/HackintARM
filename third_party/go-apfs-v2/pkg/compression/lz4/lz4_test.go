package lz4

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func frame(magic string, plain uint32, body []byte) []byte {
	b := append([]byte(nil), magic...)
	b = binary.LittleEndian.AppendUint32(b, plain)
	if magic == "bv41" {
		b = binary.LittleEndian.AppendUint32(b, uint32(len(body)))
	}
	b = append(b, body...)
	return append(b, []byte("bv4$")...)
}
func TestLZ4MalformedAndBounds(t *testing.T) {
	for _, c := range []struct {
		name string
		src  []byte
		want error
	}{
		{"empty", nil, ErrTruncated}, {"magic", []byte("oops"), ErrInvalid}, {"header", []byte("bv41"), ErrTruncated},
		{"length", []byte("bv41\x01\x00\x00\x00"), ErrTruncated},
		{"raw-extent", append([]byte("bv4-"), 0xff, 0xff, 0xff, 0xff), ErrTruncated},
		{"encoded-extent", append([]byte("bv41\x01\x00\x00\x00"), 0xff, 0xff, 0xff, 0xff), ErrTruncated},
		{"decoded-count", frame("bv41", 1, []byte{0}), ErrInvalid},
		{"literal-declared", frame("bv41", 1, []byte{0x20, 'a', 'b'}), ErrOutputFull},
		{"literal-extent", frame("bv41", 2, []byte{0x20, 'a'}), ErrTruncated},
		{"literal-extension", frame("bv41", 300, []byte{0xf0}), ErrTruncated},
		{"literal-overflow", frame("bv41", 20, []byte{0xf0, 255}), ErrOutputFull},
		{"offset-short", frame("bv41", 8, []byte{0x10, 'a', 1}), ErrTruncated},
		{"offset-zero", frame("bv41", 8, []byte{0x10, 'a', 0, 0}), ErrInvalid},
		{"offset-before-history", frame("bv41", 8, []byte{0x10, 'a', 2, 0}), ErrInvalid},
		{"match-declared", frame("bv41", 2, []byte{0x10, 'a', 1, 0}), ErrOutputFull},
		{"match-extension", frame("bv41", 100, []byte{0x1f, 'a', 1, 0}), ErrTruncated},
		{"match-overflow", frame("bv41", 30, []byte{0x1f, 'a', 1, 0, 255}), ErrOutputFull},
	} {
		t.Run(c.name, func(t *testing.T) {
			n, e := DecompressInto(make([]byte, 1024), c.src)
			if !errors.Is(e, c.want) || n < 0 || n > 1024 {
				t.Fatalf("n=%d err=%v", n, e)
			}
		})
	}
	if _, e := DecompressReader(make([]byte, 1), nil, 0); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	if _, e := DecompressReader(make([]byte, 1), bytes.NewReader(nil), -1); !errors.Is(e, ErrInvalid) {
		t.Fatal(e)
	}
	if n, e := DecompressInto(make([]byte, 1), []byte("bv4$ignored")); n != 0 || e != nil {
		t.Fatal(n, e)
	}
	if n, e := DecompressInto(nil, []byte("unread")); n != 0 || e != nil {
		t.Fatal(n, e)
	}
}

type readerFunc func([]byte, int64) (int, error)

func (f readerFunc) ReadAt(p []byte, at int64) (int, error) { return f(p, at) }
func TestLZ4ReadFailures(t *testing.T) {
	failure := errors.New("injected read error")
	plain := bytes.Repeat([]byte("a"), 70000)
	encoded := frame("bv4-", uint32(len(plain)), plain)
	for point := 1; point <= 3; point++ {
		for _, short := range []bool{false, true} {
			reads := 0
			r := readerFunc(func(p []byte, at int64) (int, error) {
				reads++
				if reads == point {
					if short {
						return 0, io.EOF
					}
					return 0, failure
				}
				return bytes.NewReader(encoded).ReadAt(p, at)
			})
			n, e := DecompressReader(make([]byte, len(plain)+1), r, int64(len(encoded)))
			if e == nil || n >= len(plain) || reads != point {
				t.Fatalf("point=%d n=%d reads=%d error=%v", point, n, reads, e)
			}
			if !short && !errors.Is(e, failure) {
				t.Fatal(e)
			}
		}
	}
	// Force a failure while reading an extended length after the token was
	// consumed, rather than while buffering the frame header.
	r := &cursor{reader: bufio.NewReader(&errorReader{data: []byte{0xf0}, err: failure}), remaining: 2}
	if _, e := decodeBlock(make([]byte, 100), 0, 100, r); !errors.Is(e, failure) {
		t.Fatal(e)
	}
	r = &cursor{reader: bufio.NewReader(&errorReader{err: failure}), remaining: 1}
	if _, e := decodeBlock(make([]byte, 1), 0, 1, r); !errors.Is(e, failure) {
		t.Fatal(e)
	}
}

type errorReader struct {
	data []byte
	err  error
}

func (r *errorReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestLZ4CrossBlockHistory(t *testing.T) {
	first := frame("bv4-", 4, []byte("abcd"))
	first = first[:len(first)-4]
	// No new literals: the second frame must reference the first frame's data.
	second := frame("bv41", 8, []byte{4, 4, 0})
	out := make([]byte, 13)
	n, e := DecompressInto(out, append(first, second...))
	if e != nil || n != 12 || string(out[:n]) != "abcdabcdabcd" {
		t.Fatal(n, string(out), e)
	}
}
func FuzzDecompress(f *testing.F) {
	for _, b := range [][]byte{[]byte("bv4$"), frame("bv4-", 4, []byte("abcd")), frame("bv41", 12, []byte{0x44, 'a', 'b', 'c', 'd', 4, 0})} {
		f.Add(b, uint32(65536))
	}
	f.Fuzz(func(t *testing.T, src []byte, capacity uint32) {
		if len(src) > 2<<20 {
			return
		}
		dst := make([]byte, int(capacity%131073))
		n, _ := DecompressInto(dst, src)
		if n < 0 || n > len(dst) {
			t.Fatal("invalid progress")
		}
	})
}
