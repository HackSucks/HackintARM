package decmpfs

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
)

func TestNativeStorageFormats(t *testing.T) {
	f, err := os.Open("../../testdata/appledouble/native/decmpfs-formats.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var fixture struct {
		Host, Compiler, SDK, Revision string
		SourceSHA256                  map[string]string
		Cases                         []struct {
			Name, Origin           string
			Type                   uint32
			Plain, Attribute, Fork []byte
		}
	}
	if err = json.NewDecoder(z).Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 14 || fixture.Host == "" || len(fixture.SourceSHA256) < 10 {
		t.Fatal("incomplete native evidence")
	}
	for _, c := range fixture.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if err := Validate(c.Attribute, 0, c.Fork); err != nil {
				t.Fatal(err)
			}
			method, err := MethodFor(c.Type)
			if err != nil {
				t.Fatal(err)
			}
			data := c.Attribute
			if StoresDataInResourceFork(c.Type) {
				data = c.Fork
			}
			h, err := NewHandle(&memSource{data: data}, uint64(len(c.Plain)), method)
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			got := make([]byte, len(c.Plain))
			n, err := h.ReadSegmentData(0, got)
			if len(got) == 0 {
				if n != 0 || !errors.Is(err, io.EOF) {
					t.Fatal(n, err)
				}
				return
			}
			if err != nil || n != len(got) || !bytes.Equal(got, c.Plain) {
				t.Fatalf("native mismatch n=%d err=%v", n, err)
			}
			for _, off := range []int{0, len(got) / 2, len(got) - 1} {
				if _, err = h.SeekSegmentOffset(0, int64(off)); err != nil {
					t.Fatal(err)
				}
				b := make([]byte, min(81, len(got)-off))
				n, err = h.ReadSegmentData(0, b)
				if err != nil || n != len(b) || !bytes.Equal(b, c.Plain[off:off+len(b)]) {
					t.Fatal("seek mismatch", err)
				}
			}
		})
	}
}
func TestStorageMalformed(t *testing.T) {
	for _, tc := range []struct {
		src          []byte
		method, size int
	}{{[]byte{1}, MethodNone, -1}, {[]byte{1}, MethodNone, 10}, {nil, MethodRawMarked, 1}, {[]byte{0}, MethodRawMarked, 1}, {nil, MethodLZBITMAP, 1}, {[]byte{1}, MethodLZBITMAP, 1}, {[]byte{0xff, 1, 2}, MethodLZBITMAP, 1}, {[]byte{1, 2}, MethodNone, 1}} {
		n := tc.size
		if err := decompressStorage(tc.src, tc.method, make([]byte, 2), &n); err == nil {
			t.Fatal("invalid input accepted", tc)
		}
	}
	n := 2
	if err := decompressStorage([]byte{0xff, 1, 2}, MethodLZBITMAP, make([]byte, 2), &n); err != nil {
		t.Fatal(err)
	}
	bad := make([]byte, 17)
	copy(bad, "fpmc")
	bad[4] = 1
	bad[8] = 2
	if err := Validate(bad, 0, nil); err == nil {
		t.Fatal("bad type1 size accepted")
	}
}

type rawSourceFailure struct {
	memSource
	short bool
	err   error
}

func (s rawSourceFailure) ReadAt(b []byte, off int64) (int, error) {
	if s.short {
		return 0, s.err
	}
	n, _ := s.memSource.ReadAt(b, off)
	return n, s.err
}
func TestStorageRawValidation(t *testing.T) {
	hdr := make([]byte, 16)
	copy(hdr, "fpmc")
	hdr[4] = 1
	for _, s := range []Source{&memSource{}, &memSource{data: make([]byte, 3803)}, &memSource{data: make([]byte, 16)}, &rawSourceFailure{memSource{data: hdr}, true, nil}, &rawSourceFailure{memSource{data: hdr}, false, errors.New("read")}} {
		if _, err := NewHandle(s, 0, MethodNone); err == nil {
			t.Fatal("invalid raw source accepted")
		}
	}
	if err := validateRawSource(&memSource{data: hdr}, 1); err == nil {
		t.Fatal("size mismatch")
	}
	if _, err := NewHandle(&rawSourceFailure{memSource{data: hdr}, false, io.EOF}, 0, MethodNone); err != nil {
		t.Fatal(err)
	}
	if err := CheckInline(make([]byte, 3803)); err == nil {
		t.Fatal("oversized compression attribute")
	}
}
