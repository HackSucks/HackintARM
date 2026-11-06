package decmpfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"
)

type zlibExtentSource struct {
	read encodeReaderFunc
	size uint64
}

func (s zlibExtentSource) Size() uint64                           { return s.size }
func (s zlibExtentSource) ReadAt(p []byte, at int64) (int, error) { return s.read(p, at) }

func TestZlibIndexExplicitPayloadLengths(t *testing.T) {
	for _, size := range []int{1, 64, BlockSize + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			plain := bytes.Repeat([]byte{'A'}, size)
			fork := make(encodeBuffer, size+4096)
			result, err := EncodeFork(t.Context(), bytes.NewReader(plain), int64(size), 4, fork)
			if err != nil {
				t.Fatal(err)
			}
			mapStart := int64(binary.BigEndian.Uint32(fork[4:8]))
			source := zlibExtentSource{size: uint64(result.Size), read: func(p []byte, at int64) (int, error) {
				if at+int64(len(p)) > mapStart {
					t.Errorf("decoder read resource-map bytes: offset=%d length=%d map=%d", at, len(p), mapStart)
					return 0, io.ErrUnexpectedEOF
				}
				return bytes.NewReader(fork[:result.Size]).ReadAt(p, at)
			}}
			h, err := NewHandle(source, uint64(size), MethodDeflate)
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			got := make([]byte, size)
			n, err := h.ReadSegmentData(0, got)
			if err != nil || n != size || !bytes.Equal(got, plain) {
				t.Fatalf("logical bytes: n=%d err=%v", n, err)
			}
			if h.CompressedBlockOffsets[len(h.CompressedBlockOffsets)-1] != uint32(mapStart) {
				t.Fatal("small offset view includes resource map")
			}
		})
	}
}

func TestZlibIndexInitializationFailures(t *testing.T) {
	failure := errors.New("descriptor changed during initialization")
	for _, fault := range []string{"first", "second", "high-offset"} {
		t.Run(fault, func(t *testing.T) {
			reads := 0
			source := zlibExtentSource{size: uint64(1)<<32 + 1024, read: func(p []byte, at int64) (int, error) {
				reads++
				if fault == "first" || fault == "second" && reads == 2 {
					return 0, failure
				}
				if len(p) != 8 || at != 264 {
					t.Fatalf("unexpected range %d/%d", at, len(p))
				}
				offset := uint32(12)
				if fault == "high-offset" {
					offset = ^uint32(0)
				}
				binary.LittleEndian.PutUint32(p, offset)
				binary.LittleEndian.PutUint32(p[4:], 5)
				return 8, nil
			}}
			h, err := NewHandle(source, 1, MethodDeflate)
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			err = h.loadZlibIndex(1)
			if fault == "high-offset" {
				if err != nil || h.largeIndex == nil || h.CompressedBlockOffsets != nil {
					t.Fatalf("checked 64-bit range: %v", err)
				}
			} else if !errors.Is(err, failure) || h.largeIndex != nil || h.CompressedBlockOffsets != nil {
				t.Fatalf("partial initialization retained: %v", err)
			}
		})
	}
}
