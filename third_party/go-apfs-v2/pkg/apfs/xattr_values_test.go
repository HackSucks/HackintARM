package apfs

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"math"
	"testing"
)

type xattrListSource struct {
	attrs              []*ExtendedAttribute
	countErr, indexErr error
	negative           bool
}

func (s xattrListSource) NumberOfExtendedAttributes() (int, error) {
	if s.negative {
		return -1, nil
	}
	return len(s.attrs), s.countErr
}
func (s xattrListSource) ExtendedAttributeByIndex(i int) (*ExtendedAttribute, error) {
	return s.attrs[i], s.indexErr
}
func sizedAttr(name string, value []byte) *ExtendedAttribute {
	reader := bytes.NewReader(value)
	return &ExtendedAttribute{AttributeValues: &AttributeValues{Name: []byte(name)}, DataStream: &DataStream{readerAt: reader, size: uint64(len(value))}}
}
func TestXattrValueNamespace(t *testing.T) {
	a := sizedAttr("test", []byte{1, 2})
	values, e := readXattrValues(xattrListSource{attrs: []*ExtendedAttribute{a, sizedAttr("empty", nil)}})
	if e != nil {
		t.Fatal(e)
	}
	if values["test"].Size() != 2 || values["empty"].Size() != 0 {
		t.Fatal(values)
	}
	b := make([]byte, 2)
	if n, e := values["test"].ReadAt(b, 0); e != nil || n != 2 || !bytes.Equal(b, []byte{1, 2}) {
		t.Fatal(n, e)
	}
	fault := errors.New("index")
	huge := sizedAttr("big", nil)
	huge.DataStream.size = math.MaxUint64
	for _, source := range []xattrListSource{{countErr: fault}, {negative: true}, {attrs: []*ExtendedAttribute{a}, indexErr: fault}, {attrs: []*ExtendedAttribute{nil}}, {attrs: []*ExtendedAttribute{{}}}, {attrs: []*ExtendedAttribute{sizedAttr("", nil)}}, {attrs: []*ExtendedAttribute{sizedAttr("a\x00b", nil)}}, {attrs: []*ExtendedAttribute{sizedAttr("bad\xff", nil)}}, {attrs: []*ExtendedAttribute{a, a}}, {attrs: []*ExtendedAttribute{huge}}, {attrs: []*ExtendedAttribute{{AttributeValues: &AttributeValues{Name: []byte("bad"), Flags: 65535}}}}} {
		if _, e = readXattrValues(source); e == nil {
			t.Fatal("invalid namespace")
		}
	}
}

type invalidValueReader struct {
	n   int
	err error
}

func (r invalidValueReader) ReadAt([]byte, int64) (int, error) { return r.n, r.err }
func TestXattrValueReaderBounds(t *testing.T) {
	v := xattrValue{reader: bytes.NewReader([]byte{1, 2}), size: 2}
	if _, e := v.ReadAt(nil, -1); !errors.Is(e, fs.ErrInvalid) {
		t.Fatal(e)
	}
	if n, e := v.ReadAt(nil, 3); e != nil || n != 0 {
		t.Fatal(n, e)
	}
	if _, e := v.ReadAt(make([]byte, 1), 2); !errors.Is(e, io.EOF) {
		t.Fatal(e)
	}
	if n, e := v.ReadAt(make([]byte, 4), 0); !errors.Is(e, io.EOF) || n != 2 {
		t.Fatal(n, e)
	}
	for _, n := range []int{-1, 2} {
		v := xattrValue{reader: invalidValueReader{n: n}, size: 1}
		if _, e := v.ReadAt(make([]byte, 1), 0); !errors.Is(e, fs.ErrInvalid) {
			t.Fatal(e)
		}
	}
	fault := errors.New("read")
	v = xattrValue{reader: invalidValueReader{err: fault}, size: 1}
	if _, e := v.ReadAt(make([]byte, 1), 0); !errors.Is(e, fault) {
		t.Fatal(e)
	}
}
