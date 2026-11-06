package apfs

import (
	"bytes"
	"errors"
	"io"
	"math"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
)

type compressionPrefixFault struct {
	data  []byte
	n     int
	err   error
	reads int
}

func (r *compressionPrefixFault) ReadAt(p []byte, off int64) (int, error) {
	r.reads++
	if off != 0 || len(p) != 16 {
		panic("compression header read exceeded fixed prefix")
	}
	copy(p, r.data)
	return r.n, r.err
}
func TestCompressionStorageHeaderBoundaries(t *testing.T) {
	header := inlineAttr(3, 65536, nil)
	for _, c := range []struct {
		name  string
		size  uint64
		data  []byte
		n     int
		err   error
		valid bool
	}{
		{"full", 16, header, 16, nil, true},
		{"full-eof", 16, header, 16, io.EOF, true},
		{"short-size", 15, header, 16, nil, false},
		{"oversized", decmpfs.MaxAttributeSize + 1, header, 16, nil, false},
		{"short-read", 16, header, 15, nil, false},
		{"read-error", 16, header, 0, io.ErrClosedPipe, false},
		{"full-error", 16, header, 16, io.ErrClosedPipe, false},
		{"bad-magic", 16, bytes.Repeat([]byte{1}, 16), 16, nil, false},
		{"unknown-type", 16, inlineAttr(0xffff, 0, nil), 16, nil, false},
		{"unrepresentable", 16, inlineAttr(3, math.MaxUint64, nil), 16, nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := &compressionPrefixFault{data: c.data, n: c.n, err: c.err}
			got, e := compressionStreamHeader(&DataStream{size: c.size, readerAt: r})
			if (e == nil) != c.valid {
				t.Fatal(got, e)
			}
			if c.valid && (got.UncompressedDataSize != 65536 || got.CompressionMethod != 3) {
				t.Fatal(got)
			}
			if (c.size < 16 || c.size > decmpfs.MaxAttributeSize) && r.reads != 0 {
				t.Fatal("invalid size caused I/O")
			}
			if c.err == io.ErrClosedPipe && !errors.Is(e, c.err) {
				t.Fatal(e)
			}
		})
	}
}
func TestCompressionStorageBindings(t *testing.T) {
	header := inlineAttr(3, 1, []byte{0xff, 'a'})
	embedded := func(b []byte) *AttributeValues {
		return &AttributeValues{Flags: ExtendedAttributeFlagEmbedded, ValueData: b}
	}
	for _, c := range []struct {
		name       string
		attributes []*AttributeValues
		attr, fork *AttributeValues
		valid      bool
	}{
		{"attribute-query", nil, nil, nil, false},
		{"missing", []*AttributeValues{}, nil, nil, false},
		{"invalid-flags", []*AttributeValues{}, &AttributeValues{}, nil, false},
		{"extent-query", []*AttributeValues{}, &AttributeValues{Flags: ExtendedAttributeFlagDataStream}, nil, false},
		{"short-header", []*AttributeValues{}, embedded([]byte{1}), nil, false},
		{"inline", []*AttributeValues{}, embedded(header), nil, true},
		{"fork-missing", []*AttributeValues{}, embedded(inlineAttr(4, 1, nil)), nil, false},
		{"fork-invalid", []*AttributeValues{}, embedded(inlineAttr(4, 1, nil)), &AttributeValues{}, false},
		{"raw-invalid", []*AttributeValues{}, embedded(inlineAttr(1, 3, []byte{1})), nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			fe := &FileEntry{FileHandle: bytes.NewReader(header), Inode: &Inode{BSDFlags: BSDFlagCompressed}, dataSize: -1, ExtendedAttributes: c.attributes, CompressedDataAttributeValues: c.attr, ResourceForkAttributeValues: c.fork}
			s, e := fe.compressedStream()
			if (e == nil) != c.valid {
				t.Fatal(s, e)
			}
			if c.valid {
				b := make([]byte, 1)
				n, e := s.ReadAt(b, 0)
				if n != 1 || e != nil || b[0] != 'a' {
					t.Fatal(b, n, e)
				}
			}
		})
	}
	// Active malformed metadata must not silently become an empty ordinary file.
	fe := &FileEntry{Inode: &Inode{BSDFlags: BSDFlagCompressed}, dataSize: -1, ExtendedAttributes: []*AttributeValues{}}
	if _, e := fe.DataSize(); e == nil {
		t.Fatal("active missing attribute accepted")
	}
}
