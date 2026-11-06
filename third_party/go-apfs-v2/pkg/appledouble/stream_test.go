package appledouble

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
)

var errStreamTest = errors.New("stream test IO failure")

type streamTestValue struct {
	size int64
	read func([]byte, int64) (int, error)
}

func (v streamTestValue) Size() int64 { return v.size }
func (v streamTestValue) ReadAt(b []byte, off int64) (int, error) {
	return v.read(b, off)
}

type streamTestWriter func([]byte) (int, error)

func (w streamTestWriter) Write(b []byte) (int, error) { return w(b) }

func streamMaterialize(t *testing.T, f *StreamFile) *File {
	t.Helper()
	read := func(value Value) []byte {
		if value == nil {
			return nil
		}
		b, err := io.ReadAll(io.NewSectionReader(value, 0, value.Size()))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	result := &File{FinderInfo: f.FinderInfo, ResourceFork: read(f.ResourceFork)}
	for _, attr := range f.Attrs {
		result.Attrs = append(result.Attrs, Attr{Name: attr.Name, Value: read(attr.Value)})
	}
	return result
}

func TestStreamNativeRecords(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/appledouble/native/records.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Records []struct {
			Name     string
			Raw      []byte
			Accepted bool
			Expected map[string][]byte
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Records) != 44 {
		t.Fatal("missing native records")
	}
	for _, tc := range fixture.Records {
		t.Run(tc.Name, func(t *testing.T) {
			input := bytes.Clone(tc.Raw)
			f, err := DecodeStream(context.Background(), bytes.NewReader(input), DefaultStreamLimits())
			if (err == nil) != tc.Accepted {
				t.Fatalf("accepted=%t: %v", tc.Accepted, err)
			}
			if !bytes.Equal(input, tc.Raw) {
				t.Fatal("modified source")
			}
			if err != nil {
				return
			}
			materialized := streamMaterialize(t, f)
			equalAttributes(t, materialized.Xattrs(), tc.Expected)
			want, err := materialized.Encode()
			if err != nil {
				t.Fatal(err)
			}
			var encoded bytes.Buffer
			if n, err := f.EncodeTo(context.Background(), &encoded, DefaultStreamLimits()); err != nil || n != int64(len(want)) || !bytes.Equal(encoded.Bytes(), want) {
				t.Fatalf("canonical parity: n=%d err=%v", n, err)
			}
		})
	}
}

func TestStreamNativeLarge(t *testing.T) {
	file, err := os.Open("../../testdata/appledouble/native/large.ad.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	raw, err := io.ReadAll(gz)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != nativeLargeSHA256 {
		t.Fatal("native corpus hash mismatch")
	}
	f, err := DecodeStream(context.Background(), bytes.NewReader(raw), DefaultStreamLimits())
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if n, err := f.EncodeTo(context.Background(), &encoded, DefaultStreamLimits()); err != nil || n != int64(len(raw)) || !bytes.Equal(raw, encoded.Bytes()) {
		t.Fatalf("native bytes differ: n=%d err=%v", n, err)
	}
}

func TestStreamEncodeOrderAndEmpty(t *testing.T) {
	f := &StreamFile{FinderInfo: [32]byte{1}, ResourceFork: bytes.NewReader([]byte{4, 5}), Attrs: []StreamAttr{
		{Name: "z", Value: bytes.NewReader([]byte{1})},
		{Name: "a", Value: nil},
		{Name: "z", Value: bytes.NewReader([]byte{2})},
		{Name: ResourceForkName, Value: bytes.NewReader([]byte{9, 8, 7})},
	}}
	before := append([]StreamAttr(nil), f.Attrs...)
	want, err := streamMaterialize(t, f).Encode()
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if _, err := f.EncodeTo(context.Background(), &encoded, DefaultStreamLimits()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.Attrs, before) || !bytes.Equal(encoded.Bytes(), want) {
		t.Fatal("encoding changed source order or canonical bytes")
	}
	decoded, err := DecodeStream(context.Background(), bytes.NewReader(encoded.Bytes()), DefaultStreamLimits())
	if err != nil {
		t.Fatal(err)
	}
	equalAttributes(t, streamMaterialize(t, decoded).Xattrs(), map[string][]byte{
		"a": nil, "z": {2}, ResourceForkName: {4, 5, 7}, FinderInfoName: f.FinderInfo[:],
	})
}

func TestStreamDecodeAliasesAndBorrowing(t *testing.T) {
	input, err := (&File{Attrs: []Attr{{Name: "a", Value: []byte{1, 2, 3}}, {Name: "b", Value: []byte{4, 5, 6}}}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	first := binary.BigEndian.Uint32(input[120:])
	binary.BigEndian.PutUint32(input[136:], first)
	f, err := DecodeStream(context.Background(), bytes.NewReader(input), DefaultStreamLimits())
	if err != nil {
		t.Fatal(err)
	}
	equalAttributes(t, streamMaterialize(t, f).Xattrs(), map[string][]byte{"a": {1, 2, 3}, "b": {1, 2, 3}})
	// This mutation deliberately violates the documented immutability contract,
	// proving returned spans borrow bytes instead of hiding payload copies.
	input[first] = 9
	if got := streamMaterialize(t, f).Attrs[0].Value; got[0] != 9 {
		t.Fatal("indexed value was copied")
	}
	limits := DefaultStreamLimits()
	limits.MaxTotalValueBytes = 5
	if _, err := DecodeStream(context.Background(), bytes.NewReader(input), limits); !errors.Is(err, ErrStreamBudget) {
		t.Fatalf("aliased logical budget: %v", err)
	}
	limits.MaxTotalValueBytes = 6
	if _, err := DecodeStream(context.Background(), bytes.NewReader(input), limits); err != nil {
		t.Fatal(err)
	}
}

func TestStreamBoundedLargeValue(t *testing.T) {
	const size = 20 << 20
	reads := 0
	value := streamTestValue{size: size, read: func(b []byte, off int64) (int, error) {
		if len(b) > 64<<10 || off < 0 || off+int64(len(b)) > size {
			t.Fatalf("unbounded read off=%d size=%d", off, len(b))
		}
		reads++
		clear(b)
		return len(b), nil
	}}
	f := &StreamFile{Attrs: []StreamAttr{{Name: "large", Value: value}}, ResourceFork: value}
	n, err := f.EncodeTo(context.Background(), io.Discard, DefaultStreamLimits())
	if err != nil || n != int64(120+entrySize("large")+2*size) || reads != 2*size/(64<<10) {
		t.Fatalf("bounded copy: n=%d reads=%d err=%v", n, reads, err)
	}
	// Index a source larger than 32-bit address space without reading payloads.
	header, _, _, err := (&StreamFile{ResourceFork: streamTestValue{size: math.MaxUint32}}).streamHeader(DefaultStreamLimits())
	if err != nil {
		t.Fatal(err)
	}
	largeSource := streamTestValue{size: int64(len(header)) + math.MaxUint32, read: func(b []byte, off int64) (int, error) {
		if off != 0 || len(b) != MaxHeader {
			t.Fatalf("index read payload: off=%d size=%d", off, len(b))
		}
		clear(b)
		copy(b, header)
		return len(b), nil
	}}
	decoded, err := DecodeStream(context.Background(), largeSource, DefaultStreamLimits())
	if err != nil || decoded.ResourceFork.Size() != math.MaxUint32 {
		t.Fatalf("large indexed fork: %v", err)
	}
}

func TestStreamEncodeValidation(t *testing.T) {
	negative := streamTestValue{size: -1}
	overflow := streamTestValue{size: math.MaxUint32 + 1}
	cases := []struct {
		name string
		file *StreamFile
	}{
		{"nil", nil},
		{"empty-name", &StreamFile{Attrs: []StreamAttr{{Name: ""}}}},
		{"long-name", &StreamFile{Attrs: []StreamAttr{{Name: strings.Repeat("n", 128)}}}},
		{"nul-name", &StreamFile{Attrs: []StreamAttr{{Name: "n\x00x"}}}},
		{"invalid-utf8", &StreamFile{Attrs: []StreamAttr{{Name: "\xff"}}}},
		{"finder-size", &StreamFile{Attrs: []StreamAttr{{Name: FinderInfoName}}}},
		{"negative-value", &StreamFile{Attrs: []StreamAttr{{Name: "n", Value: negative}}}},
		{"negative-fork", &StreamFile{ResourceFork: negative}},
		{"overflow-value", &StreamFile{Attrs: []StreamAttr{{Name: "n", Value: overflow}}}},
		{"overflow-fork", &StreamFile{ResourceFork: overflow}},
		{"sum-width", &StreamFile{Attrs: []StreamAttr{{Name: "n", Value: streamTestValue{size: math.MaxUint32}}, {Name: "o", Value: bytes.NewReader([]byte{1})}}}},
		{"header-plus-values", &StreamFile{Attrs: []StreamAttr{{Name: "n", Value: streamTestValue{size: math.MaxUint32}}}}},
		{"entry-count", &StreamFile{Attrs: make([]StreamAttr, (MaxHeader-attrEntriesOff)/16+1)}},
	}
	largeTable := &StreamFile{}
	for range 500 {
		largeTable.Attrs = append(largeTable.Attrs, StreamAttr{Name: strings.Repeat("n", 127)})
	}
	cases = append(cases, struct {
		name string
		file *StreamFile
	}{"table-size", largeTable})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			if n, err := tc.file.EncodeTo(context.Background(), &output, DefaultStreamLimits()); err == nil || n != 0 || output.Len() != 0 {
				t.Fatalf("invalid preflight wrote: %d %v", n, err)
			}
		})
	}
	if _, err := (&StreamFile{}).EncodeTo(context.Background(), nil, DefaultStreamLimits()); err == nil {
		t.Fatal("nil writer accepted")
	}
}

func TestStreamBudgets(t *testing.T) {
	f := &StreamFile{Attrs: []StreamAttr{{Name: "a", Value: bytes.NewReader([]byte{1, 2})}}, ResourceFork: bytes.NewReader([]byte{3, 4, 5})}
	var encoded bytes.Buffer
	if _, err := f.EncodeTo(context.Background(), &encoded, DefaultStreamLimits()); err != nil {
		t.Fatal(err)
	}
	for _, limits := range []StreamLimits{
		{},
		{MaxFileBytes: 1000, MaxValueBytes: 1, MaxTotalValueBytes: 1000},
		{MaxFileBytes: 1000, MaxValueBytes: 2, MaxTotalValueBytes: 1000},
		{MaxFileBytes: 1000, MaxValueBytes: 1000, MaxTotalValueBytes: 1},
		{MaxFileBytes: 1000, MaxValueBytes: 1000, MaxTotalValueBytes: 4},
		{MaxFileBytes: uint64(encoded.Len() - 1), MaxValueBytes: 1000, MaxTotalValueBytes: 1000},
	} {
		if _, err := f.EncodeTo(context.Background(), io.Discard, limits); !errors.Is(err, ErrStreamBudget) {
			t.Fatalf("encode budget %+v: %v", limits, err)
		}
		if _, err := DecodeStream(context.Background(), bytes.NewReader(encoded.Bytes()), limits); !errors.Is(err, ErrStreamBudget) {
			t.Fatalf("decode budget %+v: %v", limits, err)
		}
	}
	limits := StreamLimits{MaxFileBytes: uint64(encoded.Len()), MaxValueBytes: 3, MaxTotalValueBytes: 5}
	if _, err := f.EncodeTo(context.Background(), io.Discard, limits); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeStream(context.Background(), bytes.NewReader(encoded.Bytes()), limits); err != nil {
		t.Fatal(err)
	}
	// Check subtraction rather than addition for caller limits near uint64 max.
	total := uint64(math.MaxUint64)
	if err := (StreamLimits{MaxValueBytes: math.MaxUint64, MaxTotalValueBytes: math.MaxUint64}).addValue(1, &total); !errors.Is(err, ErrStreamBudget) {
		t.Fatal(err)
	}
	if err := (StreamLimits{}).addValue(0, &total); !errors.Is(err, ErrStreamBudget) {
		t.Fatal(err)
	}
}

func TestStreamIOFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int
		err  error
		want error
	}{
		{"negative", -1, nil, nil}, {"excess", 4, nil, nil},
		{"short-nil", 1, nil, io.ErrUnexpectedEOF}, {"short-eof", 1, io.EOF, io.ErrUnexpectedEOF},
		{"short-error", 1, errStreamTest, errStreamTest}, {"full-error", 3, errStreamTest, errStreamTest},
		{"full-eof", 3, io.EOF, io.EOF},
	} {
		t.Run("read-"+tc.name, func(t *testing.T) {
			value := streamTestValue{size: 3, read: func([]byte, int64) (int, error) { return tc.n, tc.err }}
			err := streamRead(context.Background(), value, make([]byte, 3), 0)
			if tc.name == "full-eof" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("read err=%v want=%v", err, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		name string
		n    int
		err  error
		want error
	}{
		{"negative", -1, nil, nil}, {"excess", 4, nil, nil},
		{"short", 1, nil, io.ErrShortWrite}, {"error", 1, errStreamTest, errStreamTest},
	} {
		t.Run("write-"+tc.name, func(t *testing.T) {
			var count int64
			err := streamWrite(context.Background(), streamTestWriter(func([]byte) (int, error) { return tc.n, tc.err }), []byte{1, 2, 3}, &count)
			if err == nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("write err=%v want=%v", err, tc.want)
			}
			if tc.n >= 0 && tc.n <= 3 && count != int64(tc.n) || (tc.n < 0 || tc.n > 3) && count != 0 {
				t.Fatalf("wrong written count %d", count)
			}
		})
	}
	bad := streamTestValue{size: 3, read: func([]byte, int64) (int, error) { return 0, errStreamTest }}
	for _, f := range []*StreamFile{{Attrs: []StreamAttr{{Name: "a", Value: bad}}}, {ResourceFork: bad}} {
		if n, err := f.EncodeTo(context.Background(), io.Discard, DefaultStreamLimits()); !errors.Is(err, errStreamTest) || n < attrEntriesOff {
			t.Fatalf("lost source failure/partial output: %d %v", n, err)
		}
	}
	for _, failCall := range []int{1, 2} {
		calls := 0
		writer := streamTestWriter(func(b []byte) (int, error) {
			calls++
			if calls == failCall {
				return 0, errStreamTest
			}
			return len(b), nil
		})
		if _, err := (&StreamFile{ResourceFork: bytes.NewReader([]byte{1})}).EncodeTo(context.Background(), writer, DefaultStreamLimits()); !errors.Is(err, errStreamTest) {
			t.Fatalf("writer failure %d: %v", failCall, err)
		}
	}
}

func TestStreamCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, contextValue := range []context.Context{nil, ctx} {
		if _, err := (&StreamFile{}).EncodeTo(contextValue, io.Discard, DefaultStreamLimits()); err == nil {
			t.Fatal("invalid context accepted for encode")
		}
		if _, err := DecodeStream(contextValue, bytes.NewReader(nil), DefaultStreamLimits()); err == nil {
			t.Fatal("invalid context accepted for decode")
		}
	}
	ctx, cancel = context.WithCancel(context.Background())
	w := streamTestWriter(func(b []byte) (int, error) { cancel(); return len(b), nil })
	if n, err := (&StreamFile{ResourceFork: bytes.NewReader([]byte{1})}).EncodeTo(ctx, w, DefaultStreamLimits()); !errors.Is(err, context.Canceled) || n != 120 {
		t.Fatalf("cancel after header %d %v", n, err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	v := streamTestValue{size: 1, read: func(b []byte, _ int64) (int, error) { cancel(); b[0] = 1; return 1, nil }}
	if n, err := (&StreamFile{ResourceFork: v}).EncodeTo(ctx, io.Discard, DefaultStreamLimits()); !errors.Is(err, context.Canceled) || n != 120 {
		t.Fatalf("cancel after read %d %v", n, err)
	}
}

func TestStreamDecodeFailures(t *testing.T) {
	for _, source := range []Value{nil, streamTestValue{size: -1}, bytes.NewReader(nil), streamTestValue{size: 120, read: func([]byte, int64) (int, error) { return 0, errStreamTest }}} {
		if _, err := DecodeStream(context.Background(), source, DefaultStreamLimits()); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	base, err := (&File{Attrs: []Attr{{Name: "n", Value: []byte{1}}}, ResourceFork: []byte{2}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"magic", func(b []byte) []byte { b[0] = 1; return b }},
		{"count", func(b []byte) []byte { b[25] = 3; return b }},
		{"finder-id", func(b []byte) []byte { b[29] = 2; return b }},
		{"short-attr-header", func(b []byte) []byte { return b[:82] }},
		{"attr-magic", func(b []byte) []byte { b[84] = 0; return b }},
		{"missing-entry", func(b []byte) []byte { b[119] = 2; return b }},
		{"short-name", func(b []byte) []byte { b[130] = 1; return b }},
		{"long-name", func(b []byte) []byte { b[130] = 129; return b }},
		{"name-overrun", func(b []byte) []byte { b[130] = 128; return b }},
		{"unterminated-name", func(b []byte) []byte { b[132] = 'a'; return b }},
		{"empty-name", func(b []byte) []byte { b[131] = 0; return b }},
		{"utf8-name", func(b []byte) []byte { b[131] = 255; return b }},
		{"value-overrun", func(b []byte) []byte { binary.BigEndian.PutUint32(b[120:], math.MaxUint32); return b }},
		{"finder-overrun", func(b []byte) []byte { binary.BigEndian.PutUint32(b[30:], math.MaxUint32); return b }},
		{"fork-overrun", func(b []byte) []byte { binary.BigEndian.PutUint32(b[42:], math.MaxUint32); return b }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.mutate(bytes.Clone(base))
			if _, err := DecodeStream(context.Background(), bytes.NewReader(b), DefaultStreamLimits()); err == nil {
				t.Fatal("malformed input accepted")
			}
		})
	}
	finder, err := (&File{Attrs: []Attr{{Name: FinderInfoName, Value: make([]byte, 32)}}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(finder[124:], 31)
	if _, err := DecodeStream(context.Background(), bytes.NewReader(finder), DefaultStreamLimits()); err == nil {
		t.Fatal("bad ordinary FinderInfo size accepted")
	}
}

func TestStreamDecodeEmptyOffsetsAndUnknownSecond(t *testing.T) {
	b, err := (&File{Attrs: []Attr{{Name: "empty"}}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(b[120:], math.MaxUint32)
	binary.BigEndian.PutUint32(b[42:], math.MaxUint32)
	f, err := DecodeStream(context.Background(), bytes.NewReader(b), DefaultStreamLimits())
	if err != nil || f.Attrs[0].Value.Size() != 0 || f.ResourceFork.Size() != 0 {
		t.Fatalf("empty offsets %v", err)
	}
	binary.BigEndian.PutUint32(b[38:], 99)
	binary.BigEndian.PutUint32(b[46:], math.MaxUint32)
	f, err = DecodeStream(context.Background(), bytes.NewReader(b), DefaultStreamLimits())
	if err != nil || f.ResourceFork != nil {
		t.Fatalf("unknown second entry %v", err)
	}
	// Finder-only profile does not inspect the ATTR bytes.
	binary.BigEndian.PutUint32(b[34:], 32)
	f, err = DecodeStream(context.Background(), bytes.NewReader(b[:82]), DefaultStreamLimits())
	if err != nil || len(f.Attrs) != 0 {
		t.Fatalf("finder-only %v", err)
	}
}

func FuzzStreamDecode(f *testing.F) {
	raw, err := (&File{Attrs: []Attr{{Name: "a", Value: []byte{1, 2}}}, ResourceFork: []byte{3}}).Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		limits := StreamLimits{MaxFileBytes: 1 << 20, MaxValueBytes: 1 << 20, MaxTotalValueBytes: 1 << 20}
		indexed, err := DecodeStream(context.Background(), bytes.NewReader(b), limits)
		if err != nil {
			return
		}
		materialized := streamMaterialize(t, indexed)
		var output bytes.Buffer
		if _, err := indexed.EncodeTo(context.Background(), &output, limits); err != nil {
			// Canonical expansion of aliases may exceed the file-size budget.
			if !errors.Is(err, ErrStreamBudget) && !errors.Is(err, ErrTooLarge) {
				t.Fatal(err)
			}
			return
		}
		want, err := materialized.Encode()
		if err != nil || !bytes.Equal(output.Bytes(), want) {
			t.Fatalf("canonical parity %v", err)
		}
	})
}
