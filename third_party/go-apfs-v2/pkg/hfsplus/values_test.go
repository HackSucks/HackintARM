package hfsplus

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

type testValue struct {
	size  int64
	data  []byte
	err   error
	short bool
	max   int
	reads int
}

func (v *testValue) Size() int64 { return v.size }
func (v *testValue) ReadAt(b []byte, off int64) (int, error) {
	v.reads++
	v.max = max(v.max, len(b))
	if v.short {
		return 0, io.EOF
	}
	n := copy(b, v.data[min(int(off), len(v.data)):])
	return n, v.err
}

type valueWriter struct {
	err   error
	short bool
}

func (w valueWriter) WriteAt(b []byte, _ int64) (int, error) {
	if w.short {
		return 0, nil
	}
	return len(b), w.err
}

func TestHFSValuesParity(t *testing.T) {
	for _, fold := range []bool{false, true} {
		data := bytes.Repeat([]byte("DATA"), 600000)
		large := bytes.Repeat([]byte("ATTRIBUTE"), 260000)
		fork := bytes.Repeat([]byte("FORK"), 550000)
		finder := make([]byte, 32)
		finder[4] = 1
		eager := &Entry{Mode: os.ModeDir | 0755, Xattrs: map[string][]byte{"root": large}, Children: []*Entry{{Name: "file", Mode: 0644, Data: data, ResourceFork: fork, Xattrs: map[string][]byte{"large": large, "empty": {}, finderInfoName: finder}, LinkGroup: 9}}}
		alias := *eager.Children[0]
		alias.Name = "alias"
		eager.Children = append(eager.Children, &alias)
		lazy := &Entry{Mode: eager.Mode, XattrValues: map[string]appledouble.Value{"root": bytes.NewReader(large)}}
		var sources []*testValue
		for _, e := range eager.Children {
			c := *e
			c.Data = nil
			c.ResourceFork = nil
			c.Xattrs = nil
			c.XattrValues = map[string]appledouble.Value{}
			d := &testValue{size: int64(len(data)), data: data}
			f := &testValue{size: int64(len(fork)), data: fork}
			a := &testValue{size: int64(len(large)), data: large}
			sources = append(sources, d, f, a)
			c.DataValue = d
			c.ResourceForkValue = f
			c.XattrValues["large"] = a
			c.XattrValues["empty"] = bytes.NewReader(nil)
			c.XattrValues[finderInfoName] = bytes.NewReader(finder)
			lazy.Children = append(lazy.Children, &c)
		}
		one, two := &memWriterAt{}, &memWriterAt{}
		opts := &CreateOptions{CaseInsensitive: fold}
		if err := CreateImage(one, 0, "VALUES", eager, opts); err != nil {
			t.Fatal(err)
		}
		if err := CreateImage(two, 0, "VALUES", lazy, opts); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(one.b, two.b) {
			t.Fatal("borrowed writer changed image bytes")
		}
		for _, v := range sources {
			if v.max > contentBufferSize {
				t.Fatal("unbounded read", v.max)
			}
		}
		v, err := New(bytes.NewReader(two.b))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{".", "file", "alias"} {
			values, err := v.XattrValues(name)
			if err != nil {
				t.Fatal(err)
			}
			want, err := v.Xattrs(name)
			if err != nil {
				t.Fatal(err)
			}
			if len(values) != len(want) {
				t.Fatal("attribute count")
			}
			for name, value := range values {
				got := make([]byte, value.Size())
				if err := readValue(value, got); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want[name]) {
					t.Fatal(name)
				}
			}
		}
		if _, err := v.XattrValues("../bad"); err == nil {
			t.Fatal("invalid path accepted")
		}
	}
}
func TestHFSValuesValidation(t *testing.T) {
	bad := &testValue{size: -1}
	fail := &testValue{size: 1, short: true}
	reader := bytes.NewReader([]byte("x"))
	cases := []*Entry{
		nil, {Children: []*Entry{nil}},
		{Xattrs: map[string][]byte{"x": nil}, XattrValues: map[string]appledouble.Value{"x": reader}},
		{XattrValues: map[string]appledouble.Value{"x": nil}},
		{XattrValues: map[string]appledouble.Value{"x": bad}},
		{XattrValues: map[string]appledouble.Value{"x": fail}},
		{XattrValues: map[string]appledouble.Value{finderInfoName: reader}},
		{DataValue: reader, Data: []byte{}}, {DataValue: bad}, {DataValue: reader, Mode: os.ModeDir}, {DataValue: reader, Mode: os.ModeSymlink}, {DataValue: reader, Size: 1},
		{ResourceForkValue: bad}, {ResourceForkValue: reader, ResourceFork: []byte{}}, {ResourceForkValue: reader, Mode: os.ModeDir},
	}
	for i, e := range cases {
		if _, err := prepareValueTree(e, 4096); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	for _, name := range []string{"", "a\x00b", "\xff", strings.Repeat("x", 128), decmpfs.ResourceForkName} {
		for _, lazy := range []bool{false, true} {
			e := &Entry{}
			if lazy {
				e.XattrValues = map[string]appledouble.Value{name: reader}
			} else {
				e.Xattrs = map[string][]byte{name: nil}
			}
			if _, err := prepareValueTree(e, 4096); err == nil {
				t.Fatal("name accepted", name)
			}
		}
	}
	if _, err := valueSize(&testValue{size: 1 << 62}, 4096); err == nil {
		t.Fatal("oversize")
	}
	changed := &testValue{size: 1, data: []byte("x")}
	e, err := prepareValueTree(&Entry{DataValue: changed}, 4096)
	if err != nil {
		t.Fatal(err)
	}
	changed.size = 2
	if _, err = e.Open(); err == nil {
		t.Fatal("changed size")
	}
	if err := readValue(&testValue{size: 1, data: []byte("x"), err: errors.New("read")}, make([]byte, 1)); err == nil {
		t.Fatal("read error")
	}
	if err := readValue(&testValue{size: 1, data: []byte("x"), err: io.EOF}, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err = prepareValueTree(&Entry{XattrValues: map[string]appledouble.Value{"empty": bytes.NewReader(nil)}}, 4096); err != nil {
		t.Fatal(err)
	}
}
func TestHFSValuesWriteFailures(t *testing.T) {
	for _, tc := range []struct {
		v *testValue
		w valueWriter
		n int
	}{{&testValue{size: 2}, valueWriter{}, 1}, {&testValue{size: 1, short: true}, valueWriter{}, 1}, {&testValue{size: 1, data: []byte("x"), err: errors.New("read")}, valueWriter{}, 1}, {&testValue{size: 1, data: []byte("x")}, valueWriter{err: errors.New("write")}, 1}, {&testValue{size: 1, data: []byte("x")}, valueWriter{short: true}, 1}} {
		if err := writeValue(tc.w, 0, tc.v, tc.n); err == nil {
			t.Fatal("failure accepted")
		}
	}
	if err := writeValue(valueWriter{}, 0, &testValue{}, 0); err != nil {
		t.Fatal(err)
	}
	if err := validateCompressedValue(&Entry{}); err != nil {
		t.Fatal(err)
	}
	if err := validateCompressedValue(&Entry{XattrValues: map[string]appledouble.Value{decmpfs.AttributeName: &testValue{size: 16, short: true}}}); err == nil {
		t.Fatal("short header")
	}
}

func TestHFSValuesReaderFailures(t *testing.T) {
	fixture := func() (*Volume, *entry) {
		w := &memWriterAt{}
		if err := CreateImage(w, 0, "V", &Entry{Children: []*Entry{{Name: "f", Mode: 0644}}}, nil); err != nil {
			t.Fatal(err)
		}
		v, err := New(bytes.NewReader(w.b))
		if err != nil {
			t.Fatal(err)
		}
		e, err := v.lookup("f")
		if err != nil {
			t.Fatal(err)
		}
		if err = v.loadAttributes(); err != nil {
			t.Fatal(err)
		}
		return v, e
	}
	v, e := fixture()
	if _, err := v.xattrValues(&entry{}); err == nil {
		t.Fatal("missing catalog")
	}
	id, _ := entryFileID(e)
	key := attrKey{id, "x"}
	if _, err := v.attributeReader(id, "missing"); err == nil {
		t.Fatal("missing attribute")
	}
	v.attributes[key] = &attrRecord{}
	if _, err := v.attributeReader(id, "x"); err == nil {
		t.Fatal("missing fork")
	}
	v.attrNames[id] = []string{"x"}
	if _, err := v.XattrValues("f"); err == nil {
		t.Fatal("reader error hidden")
	}
	v.attributes[key] = &attrRecord{hasFork: true, fork: ForkData{TotalBlocks: 2}}
	if _, err := v.attributeReader(id, "x"); err == nil {
		t.Fatal("missing extents")
	}
	v.attributes[key] = &attrRecord{hasFork: true, fork: ForkData{LogicalSize: 4097, TotalBlocks: 1, Extents: [8]ExtentDescriptor{{BlockCount: 1}}}}
	if _, err := v.attributeReader(id, "x"); err == nil {
		t.Fatal("short extents")
	}
	rec := &attrRecord{hasFork: true, fork: ForkData{LogicalSize: 8192, TotalBlocks: 2, Extents: [8]ExtentDescriptor{{BlockCount: 1}}}, overflow: []overflowRun{{startBlock: 0}, {startBlock: 1, extents: [8]ExtentDescriptor{{BlockCount: 1}}}}}
	v.attributes[key] = rec
	if value, err := v.attributeReader(id, "x"); err != nil || value.Size() != 8192 {
		t.Fatal(value, err)
	}
	v.attrNames[id] = []string{finderInfoName}
	finderKey := attrKey{id, finderInfoName}
	v.attributes[finderKey] = &attrRecord{inline: make([]byte, 33)}
	if _, err := v.xattrValues(e); err == nil {
		t.Fatal("oversize finder")
	}
	v.attributes[finderKey] = &attrRecord{inline: []byte{1}}
	if _, err := v.xattrValues(e); err == nil {
		t.Fatal("finder conflict")
	}
	v.attributes[finderKey] = &attrRecord{inline: []byte{}}
	if _, err := v.xattrValues(e); err != nil {
		t.Fatal(err)
	}
	v.attributes[finderKey] = &attrRecord{hasFork: true, fork: ForkData{LogicalSize: 32, TotalBlocks: 1, Extents: [8]ExtentDescriptor{{BlockCount: 1, StartBlock: 999999}}}}
	if _, err := v.xattrValues(e); err == nil {
		t.Fatal("unreadable finder")
	}
	v.attrNames[id] = nil
	e.file.ResourceFork = ForkData{LogicalSize: 4097, TotalBlocks: 1, Extents: [8]ExtentDescriptor{{BlockCount: 1}}}
	if _, err := v.xattrValues(e); err == nil {
		t.Fatal("short resource fork")
	}
	v, e = fixture()
	v.attributes = nil
	v.hdr.AttributesFile = ForkData{LogicalSize: 4097, TotalBlocks: 1, Extents: [8]ExtentDescriptor{{BlockCount: 1}}}
	if _, err := v.xattrValues(e); err == nil {
		t.Fatal("bad attribute tree")
	}
	if err := validateCompressedValue(&Entry{Xattrs: map[string][]byte{decmpfs.AttributeName: make([]byte, 16)}}); err == nil {
		t.Fatal("bad compression")
	}
}

func TestHFSValuesLayoutBounds(t *testing.T) {
	for _, tc := range []struct {
		data      uint64
		requested int64
	}{{1 << 32, 0}, {0, -1}, {0, 1 << 60}} {
		if err := validateLayoutBlocks(tc.data, 1, 1, 4096, tc.requested); err == nil {
			t.Fatal("overflow accepted")
		}
	}
	if err := validateLayoutBlocks(4, 1, 1, 4096, 0); err != nil {
		t.Fatal(err)
	}
}
