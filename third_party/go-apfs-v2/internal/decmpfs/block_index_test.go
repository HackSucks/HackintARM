package decmpfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"
)

type indexSource struct {
	data    []byte
	failAt  int64
	err     error
	short   bool
	maximum int
}

func (s *indexSource) Size() uint64 { return uint64(len(s.data)) }
func (s *indexSource) ReadAt(p []byte, at int64) (int, error) {
	s.maximum = max(s.maximum, len(p))
	if at >= s.failAt && s.failAt >= 0 {
		if s.short {
			return 0, io.EOF
		}
		return 0, s.err
	}
	if at < 0 || at >= int64(len(s.data)) {
		return 0, io.EOF
	}
	n := copy(p, s.data[at:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func largeIndexFixture(t *testing.T, zlib bool) (*Handle, *indexSource, uint64, uint32) {
	t.Helper()
	count := uint32(16384)
	start, width := uint64(0), uint64(4)
	end := (uint64(count) + 1) * 4
	method := MethodLZVN
	marker := byte(6)
	if zlib {
		count = 8192
		start, width = 264, 8
		end = start + uint64(count)*width
		method = MethodDeflate
		marker = 255
	}
	s := &indexSource{data: make([]byte, end+uint64(count)*2), failAt: -1}
	if zlib {
		binary.BigEndian.PutUint32(s.data, 256)
		binary.LittleEndian.PutUint32(s.data[260:], count)
	}
	for i := uint32(0); i < count; i++ {
		entry := s.data[start+uint64(i)*width:]
		position := uint32(end) + i*2
		if zlib {
			binary.LittleEndian.PutUint32(entry, position-260)
			binary.LittleEndian.PutUint32(entry[4:], 2)
		} else {
			binary.LittleEndian.PutUint32(entry, position)
		}
		copy(s.data[position:], []byte{marker, 'A'})
	}
	if !zlib {
		binary.LittleEndian.PutUint32(s.data[uint64(count)*4:], uint32(len(s.data)))
	}
	h, err := NewHandle(s, uint64(count-1)*BlockSize+1, method)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Error(err)
		}
	})
	return h, s, start, count
}
func TestLargeCompressionIndexBoundedRanges(t *testing.T) {
	for _, zlib := range []bool{false, true} {
		t.Run(fmt.Sprint(zlib), func(t *testing.T) {
			h, s, _, count := largeIndexFixture(t, zlib)
			if err := h.loadCompressedBlockOffsets(); err != nil {
				t.Fatal(err)
			}
			if h.largeIndex == nil || h.CompressedBlockOffsets != nil || h.NumberOfCompressedBlocks != count {
				t.Fatal("large index was not retained as ranges")
			}
			if s.maximum > BlockSize {
				t.Fatalf("unbounded table read: %d", s.maximum)
			}
			if err := h.loadCompressedBlockOffsets(); err == nil {
				t.Fatal("duplicate initialization succeeded")
			}
			for _, block := range []uint32{0, count / 2, count - 1} {
				at, n, err := h.largeIndex.block(s, block)
				if err != nil || n != 2 || at != int64(h.largeIndex.end)+int64(block)*2 {
					t.Fatalf("block %d: %d %d %v", block, at, n, err)
				}
			}
			if _, _, err := h.largeIndex.block(s, count); err == nil {
				t.Fatal("out of range block accepted")
			}
			if _, err := h.SeekSegmentOffset(0, int64(h.UncompressedDataSize)-1); err != nil {
				t.Fatal(err)
			}
			var b [1]byte
			if n, err := h.ReadSegmentData(0, b[:]); err != nil || n != 1 || b[0] != 'A' {
				t.Fatalf("tail=%q n=%d error=%v", b, n, err)
			}
			if _, err := h.ReadSegmentData(0, b[:]); err != io.EOF {
				t.Fatalf("end: %v", err)
			}
		})
	}
}

func TestLargeCompressionIndexRejectsMalformedTables(t *testing.T) {
	fault := errors.New("index read failure")
	for _, zlib := range []bool{false, true} {
		for _, name := range []string{"count", "extent", "error", "short", "before", "overlap", "zero", "wide", "beyond", "changed", "changed-error", "changed-short"} {
			t.Run(fmt.Sprintf("%t/%s", zlib, name), func(t *testing.T) {
				h, s, start, count := largeIndexFixture(t, zlib)
				indexEnd := uint32((uint64(count) + 1) * 4)
				if zlib {
					indexEnd = uint32(start) + count*8
				}
				entry := s.data[start:]
				width := 4
				if zlib {
					width = 8
				}
				position := func(e []byte, n uint32) {
					if zlib {
						n -= 260
					}
					binary.LittleEndian.PutUint32(e, n)
				}
				if name == "changed" || name == "changed-error" || name == "changed-short" {
					if err := h.loadLargeIndex(start, count, zlib); err != nil {
						t.Fatal(err)
					}
					if name == "changed" {
						position(entry, 0)
					} else {
						s.failAt = int64(start)
						s.err = fault
						s.short = name == "changed-short"
					}
					_, _, err := h.largeIndex.block(s, 0)
					if err == nil {
						t.Fatal("changed index accepted")
					}
					if name == "changed-error" && !errors.Is(err, fault) {
						t.Fatal(err)
					}
					if name == "changed-short" && !errors.Is(err, io.ErrUnexpectedEOF) {
						t.Fatal(err)
					}
					return
				}
				switch name {
				case "count":
					h.UncompressedDataSize++
				case "extent":
					s.data = s.data[:indexEnd-1]
				case "error", "short":
					s.failAt = int64(start)
					s.err = fault
					s.short = name == "short"
				case "before":
					position(entry, indexEnd-1)
				case "overlap":
					position(entry[width:], indexEnd-1)
				case "zero":
					if zlib {
						binary.LittleEndian.PutUint32(entry[4:], 0)
					} else {
						position(entry[4:], indexEnd)
					}
				case "wide":
					if zlib {
						binary.LittleEndian.PutUint32(entry[4:], BlockSize+2)
					} else {
						position(entry[4:], indexEnd+BlockSize+2)
					}
				case "beyond":
					position(entry, uint32(len(s.data))+1)
				}
				if name == "count" {
					h.UncompressedDataSize += BlockSize
				}
				err := h.loadLargeIndex(start, count, zlib)
				if err == nil {
					t.Fatal("invalid table accepted")
				}
				if name == "error" && !errors.Is(err, fault) {
					t.Fatal(err)
				}
				if name == "short" && !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatal(err)
				}
				if h.largeIndex != nil {
					t.Fatal("failed initialization retained state")
				}
			})
		}
	}
	h, _, start, _ := largeIndexFixture(t, true)
	if err := h.loadLargeIndex(start, 0, true); err == nil {
		t.Fatal("zero count accepted")
	}
	h, s, _, _ := largeIndexFixture(t, false)
	binary.LittleEndian.PutUint32(s.data, BlockSize+1)
	if err := h.loadCompressedBlockOffsets(); err == nil {
		t.Fatal("unaligned table accepted")
	}
}
