package appledouble

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"testing"
)

func TestNativeLargeValue(t *testing.T) {
	f, err := os.Open("../../testdata/appledouble/native/large.ad.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	raw, err := io.ReadAll(io.LimitReader(z, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	// Raw native copyfile output, including the host's provenance attribute.
	if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != nativeLargeSHA256 {
		t.Fatalf("native fixture hash: %s", got)
	}
	decoded, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Xattrs()["com.example.large"], bytes.Repeat([]byte{0x5a}, 300*1024)) {
		t.Fatal("native large value differs")
	}
	encoded, err := decoded.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, encoded) {
		t.Fatal("native large sidecar changed on re-encoding")
	}
}

func TestLargeValuesAndFork(t *testing.T) {
	for _, size := range []int{65535, 65536, 65537, 300 * 1024, 1 << 20, 16 << 20} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			value := bytes.Repeat([]byte{0x7b}, size)
			f := FromXattrs(map[string][]byte{"a": value, "b": value, ResourceForkName: value})
			raw, err := f.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if binary.BigEndian.Uint32(raw[96:]) != 152 || int(binary.BigEndian.Uint32(raw[92:])) != 152+2*size {
				t.Fatal("values incorrectly counted against the header/table limit")
			}
			decoded, err := Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			if len(decoded.Attrs) != 2 || !bytes.Equal(decoded.Attrs[0].Value, value) || !bytes.Equal(decoded.Attrs[1].Value, value) || !bytes.Equal(decoded.ResourceFork, value) {
				t.Fatal("large metadata was lost")
			}
		})
	}
}

func TestEntryTableLimit(t *testing.T) {
	// 4087 sixteen-byte records and two twenty-byte records exactly fill the
	// largest four-byte-aligned table accepted by native copyfile (65552).
	f := &File{}
	for range 4087 {
		f.Attrs = append(f.Attrs, Attr{Name: "x"})
	}
	f.Attrs = append(f.Attrs, Attr{Name: "longname"}, Attr{Name: "longname"})
	raw, err := f.Encode()
	if err != nil || len(raw) != 65552 {
		t.Fatal(len(raw), err)
	}
	f.Attrs = append(f.Attrs, Attr{Name: "x"})
	if _, err := f.Encode(); err != ErrTooLarge {
		t.Fatal(err)
	}
	// A long name takes more space without overflowing the entry count.
	f = &File{Attrs: make([]Attr, 468)}
	for i := range f.Attrs {
		f.Attrs[i].Name = strings.Repeat("n", 127)
	}
	if _, err := f.Encode(); err != ErrTooLarge {
		t.Fatal(err)
	}
}

func TestEmptyValueOffset(t *testing.T) {
	raw, err := FromXattrs(map[string][]byte{"a": {}, "b": []byte("value")}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(raw[120:]) != 0 || binary.BigEndian.Uint32(raw[124:]) != 0 {
		t.Fatal("native empty attribute uses zero offset and length")
	}
	if binary.BigEndian.Uint32(raw[136:]) != 152 {
		t.Fatal("empty value consumed data bytes")
	}
	f, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	v, present := f.Xattrs()["a"]
	if !present || len(v) != 0 {
		t.Fatal("empty attribute became absent")
	}
}

func TestEncodedSizeBounds(t *testing.T) {
	for _, tc := range []struct{ header, values, fork uint64 }{
		{MaxHeader + 1, 0, 0}, {120, math.MaxUint32, 0},
		{120, 0, uint64(math.MaxUint32) + 1}, {math.MaxUint64, math.MaxUint64, math.MaxUint64},
	} {
		if _, err := encodedSize(tc.header, tc.values, tc.fork); err != ErrTooLarge {
			t.Fatal(tc, err)
		}
	}
	for _, tc := range []struct{ header, values, fork uint64 }{
		{120, 0, 0}, {120, 65536, 1}, {120, math.MaxUint32 - 120, math.MaxUint32},
	} {
		got, err := encodedSize(tc.header, tc.values, tc.fork)
		want := tc.header + tc.values + tc.fork
		if want > uint64(math.MaxInt) {
			if err != ErrTooLarge {
				t.Fatal("32-bit address-space overflow", err)
			}
		} else if err != nil || uint64(got) != want {
			t.Fatal(tc, got, err)
		}
	}
}
