package apfswrite

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

type valueProbe struct {
	size    int64
	data    []byte
	err     error
	count   int
	readMax int
}

func (v *valueProbe) Size() int64 { return v.size }
func (v *valueProbe) ReadAt(b []byte, off int64) (int, error) {
	v.readMax = max(v.readMax, len(b))
	v.count++
	if v.err != nil {
		return 0, v.err
	}
	if off < 0 || off >= int64(len(v.data)) {
		return 0, io.EOF
	}
	n := copy(b, v.data[off:])
	if n < len(b) {
		return n, io.EOF
	}
	return n, nil
}
func TestValuePreparation(t *testing.T) {
	fork := bytes.Repeat([]byte{3}, 9000)
	large := &valueProbe{size: 500000}
	e := &Entry{Name: "file", DataValue: bytes.NewReader([]byte("data")), Xattrs: map[string][]byte{"bytes": {1}}, XattrValues: map[string]appledouble.Value{"small": bytes.NewReader([]byte{2}), "empty": bytes.NewReader(nil), resourceForkName: bytes.NewReader(fork), "large": large, securityName: bytes.NewReader(nil), finderInfoName: bytes.NewReader(make([]byte, 32))}}
	embedded, streamed, flags, _, err := prepareXattrs(e)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(embedded["small"], []byte{2}) || embedded["empty"] == nil || streamed[resourceForkName].Size() != 9000 || large.count != 0 || flags&(inodeHasRsrcFork|inodeHasSecurityEA|inodeHasFinderInfo) != (inodeHasRsrcFork|inodeHasSecurityEA|inodeHasFinderInfo) {
		t.Fatal("bad prepared layout")
	}
}
func TestValueInvalidInputs(t *testing.T) {
	for _, e := range []*Entry{
		{Data: []byte{}, DataValue: bytes.NewReader(nil)}, {Mode: os.ModeDir, DataValue: bytes.NewReader(nil)}, {Mode: os.ModeSymlink, DataValue: bytes.NewReader(nil)},
		{DataValue: &valueProbe{size: -1}}, {DataValue: &valueProbe{size: maxStreamSize + 1}},
		{Xattrs: map[string][]byte{"x": nil}, XattrValues: map[string]appledouble.Value{"x": bytes.NewReader(nil)}},
		{XattrValues: map[string]appledouble.Value{"x": nil}}, {XattrValues: map[string]appledouble.Value{"x": &valueProbe{size: -1}}},
		{XattrValues: map[string]appledouble.Value{"": bytes.NewReader(nil)}}, {XattrValues: map[string]appledouble.Value{"nul\x00": bytes.NewReader(nil)}}, {XattrValues: map[string]appledouble.Value{symlinkName: bytes.NewReader(nil)}},
		{XattrValues: map[string]appledouble.Value{"x": &valueProbe{size: 1}}},
	} {
		if _, _, _, _, err := prepareXattrs(e); err == nil {
			t.Fatalf("accepted %+v", e)
		}
	}
	compressed := uint32(0x20)
	if _, _, _, _, err := prepareXattrs(&Entry{BSDFlags: &compressed}); err == nil {
		t.Fatal("flags mismatch")
	}
}
func TestValueCompressionLayout(t *testing.T) {
	header := make([]byte, 16)
	copy(header, "fpmc")
	binary.LittleEndian.PutUint32(header[4:], 4)
	binary.LittleEndian.PutUint64(header[8:], 1)
	e := &Entry{XattrValues: map[string]appledouble.Value{decmpfsName: bytes.NewReader(header), resourceForkName: bytes.NewReader([]byte{1})}}
	if _, _, _, _, err := prepareXattrs(e); err != nil {
		t.Fatal(err)
	}
	e.DataValue = bytes.NewReader([]byte{1})
	if _, _, _, _, err := prepareXattrs(e); err == nil {
		t.Fatal("data accepted with compression")
	}
	e.DataValue = nil
	e.XattrValues[decmpfsName] = &valueProbe{size: 16, err: io.ErrClosedPipe}
	if _, _, _, _, err := prepareXattrs(e); !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	e.XattrValues[decmpfsName] = bytes.NewReader(header)
	e.XattrValues[resourceForkName] = &valueProbe{size: -1}
	if _, _, _, _, err := prepareXattrs(e); err == nil {
		t.Fatal("invalid fork size")
	}
}
func TestValueCopyBoundaries(t *testing.T) {
	probe := &valueProbe{size: 3, data: []byte{1, 2, 3}}
	e := &builderEntry{dataValue: probe, valueSize: 3}
	buf := make([]byte, 6)
	n, err := e.copyStream(buf, 0)
	if err != nil || n != 3 || probe.readMax != 3 {
		t.Fatal(n, err)
	}
	if n, err = e.copyStream(buf, 3); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	probe.size = 4
	if _, err = e.copyStream(buf, 0); err == nil {
		t.Fatal("size changed")
	}
	probe.size = -1
	if _, err = e.copyStream(buf, 0); err == nil {
		t.Fatal("negative size")
	}
	probe.size = 3
	probe.data = nil
	if _, err = e.copyStream(buf, 0); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	e = &builderEntry{data: []byte{1, 2}}
	if n, err = e.copyStream(buf, 0); err != nil || n != 2 {
		t.Fatal(n, err)
	}
	if n, err = e.copyStream(buf, 2); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	fullErr := &fullErrorValue{}
	if err = readValueExact(fullErr, make([]byte, 1), 0); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	fullErr.err = io.EOF
	if err = readValueExact(fullErr, make([]byte, 1), 0); err != nil {
		t.Fatal(err)
	}
}

type fullErrorValue struct{ err error }

func (v *fullErrorValue) Size() int64 { return 1 }
func (v *fullErrorValue) ReadAt(b []byte, _ int64) (int, error) {
	if v.err != nil {
		return len(b), v.err
	}
	return len(b), io.ErrClosedPipe
}

type valueDiscard struct{ writes int }

func (w *valueDiscard) WriteAt(b []byte, _ int64) (int, error) { w.writes++; return len(b), nil }
func TestValuePreflightBeforeOutput(t *testing.T) {
	for _, which := range []string{"root", "alias-data", "alias-xattr", "aggregate", "automatic-overflow", "image-too-small"} {
		t.Run(which, func(t *testing.T) {
			root := &Entry{Mode: os.ModeDir}
			size := int64(32 << 20)
			switch which {
			case "root":
				root.DataValue = bytes.NewReader(nil)
			case "alias-data":
				root.Children = []*Entry{{Name: "a", LinkGroup: 1}, {Name: "b", LinkGroup: 1, Data: []byte{}, DataValue: bytes.NewReader(nil)}}
			case "alias-xattr":
				root.Children = []*Entry{{Name: "a", LinkGroup: 1}, {Name: "b", LinkGroup: 1, Xattrs: map[string][]byte{"x": nil}, XattrValues: map[string]appledouble.Value{"x": bytes.NewReader(nil)}}}
			case "aggregate", "automatic-overflow":
				n := 129
				if which == "automatic-overflow" {
					n = 128
					size = 0
				}
				root.XattrValues = map[string]appledouble.Value{}
				for i := 0; i < n; i++ {
					root.XattrValues[fmt.Sprintf("value%d", i)] = &valueProbe{size: maxStreamSize}
				}
			case "image-too-small":
				root.Children = []*Entry{{Name: "large", DataValue: &valueProbe{size: 3 << 30}}}
			}
			sink := &valueDiscard{}
			if e := CreateContainer(sink, size, &CreateOptions{Root: root}); e == nil {
				t.Fatal("accepted invalid layout")
			}
			if sink.writes != 0 {
				t.Fatal("wrote before refusal")
			}
		})
	}
}
func TestValueWriteFailure(t *testing.T) {
	source := &valueProbe{size: 5000, err: io.ErrClosedPipe}
	sink := &valueDiscard{}
	if e := CreateContainer(sink, 32<<20, &CreateOptions{Root: &Entry{Children: []*Entry{{Name: "file", DataValue: source}}}}); !errors.Is(e, io.ErrClosedPipe) {
		t.Fatal(e)
	}
}
