package largefork

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"testing"
)

func TestCarrierLargeValueBoundaries(t *testing.T) {
	v := &Value{}
	if v.Size() != 4294967313 {
		t.Fatal(v.Size())
	}
	for _, test := range []struct {
		offset int64
		want   []byte
	}{{0, []byte("fork-start")}, {(1 << 32) - 8, []byte("boundary-crossing")}, {1 << 32, []byte("-crossing")}, {Size - 2, []byte{0, 255}}, {100, make([]byte, 10)}} {
		got := make([]byte, len(test.want))
		n, err := v.ReadAt(got, test.offset)
		if err != nil || n != len(got) || !bytes.Equal(got, test.want) {
			t.Fatal(test.offset, n, got, err)
		}
	}
	if v.Reads != 5 || v.MaxRead != 17 {
		t.Fatal(v)
	}
	if n, err := v.ReadAt(make([]byte, 3), Size-1); n != 1 || !errors.Is(err, io.EOF) {
		t.Fatal(n, err)
	}
	if n, err := v.ReadAt(make([]byte, 1), Size); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatal(n, err)
	}
	if n, err := v.ReadAt(nil, Size); n != 0 || err != nil {
		t.Fatal(n, err)
	}
	if n, err := v.ReadAt(nil, -1); n != 0 || !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(n, err)
	}
}
