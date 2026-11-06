package decmpfs

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/lzbitmap"
	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/lzfse"
)

// EncodedFork describes a completed compression resource fork. Attribute holds
// the native decmpfs header; Size is the exact extent written to the fork.
// Encoding does not install attributes, truncate caller files or change flags.
type EncodedFork struct {
	Attribute [HeaderSize]byte
	Size      int64
}

// EncodeFork writes native compression blocks and their index through bounded
// source reads and positioned destination writes. It never retains a whole
// payload or index. The caller owns both handles and must discard partial output
// on failure. Cancellation is observed between I/O and codec calls.
//
// kind selects a native codec (3/4, 7/8, 9/10, 11/12 or 13/14); the returned
// header names its resource-fork form. This format primitive deliberately does
// not decide whether a host should compress a file or use inline storage.
func EncodeFork(ctx context.Context, source io.ReaderAt, size int64, kind uint32, destination io.WriterAt) (EncodedFork, error) {
	return encodeFork(ctx, source, size, kind, destination, nil)
}

// accept examines each encoded block before any of that block is written. The
// policy encoder uses it to select inline storage or decline insufficient savings.
func encodeFork(ctx context.Context, source io.ReaderAt, size int64, kind uint32, destination io.WriterAt, accept func([]byte) error) (EncodedFork, error) {
	if err := ctx.Err(); err != nil {
		return EncodedFork{}, err
	}
	if source == nil || destination == nil || size <= 0 {
		return EncodedFork{}, fmt.Errorf("invalid compression source or destination")
	}
	if kind&1 != 0 {
		kind++
	}
	if kind != 4 && kind != 8 && kind != 10 && kind != 12 && kind != 14 {
		return EncodedFork{}, fmt.Errorf("unsupported compression type %d", kind)
	}
	blocks := uint64((size-1)/BlockSize + 1)
	width, base := uint64(4), uint64(0)
	entries := blocks + 1
	if kind == 4 {
		width, base, entries = 8, 264, blocks
	}
	if entries > (math.MaxUint32-base)/width {
		return EncodedFork{}, fmt.Errorf("compression index exceeds native 32-bit offsets")
	}
	offset := int64(base + entries*width)
	write := func(data []byte, at int64) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := destination.WriteAt(data, at)
		if n != len(data) {
			err = errors.Join(io.ErrShortWrite, err)
		}
		return errors.Join(err, ctx.Err())
	}
	buffer := make([]byte, BlockSize)
	for block := uint64(0); block < blocks; block++ {
		if err := ctx.Err(); err != nil {
			return EncodedFork{}, err
		}
		at := int64(block) * BlockSize
		plain := buffer[:min(int64(BlockSize), size-at)]
		n, err := source.ReadAt(plain, at)
		if n != len(plain) {
			return EncodedFork{}, errors.Join(io.ErrUnexpectedEOF, err, ctx.Err())
		}
		if err != nil && err != io.EOF {
			return EncodedFork{}, errors.Join(err, ctx.Err())
		}
		if err = ctx.Err(); err != nil {
			return EncodedFork{}, err
		}
		encoded, err := encodeBlock(plain, kind)
		if err != nil {
			return EncodedFork{}, err
		}
		if err := ctx.Err(); err != nil {
			return EncodedFork{}, err
		}
		if accept != nil {
			if err := accept(encoded); err != nil {
				return EncodedFork{}, err
			}
		}
		if kind == 4 && block == 0 {
			if err := write(make([]byte, 264), 0); err != nil {
				return EncodedFork{}, err
			}
		}
		if err := checkEncodedExtent(offset, int64(len(encoded))); err != nil {
			return EncodedFork{}, err
		}
		if err = write(encoded, offset); err != nil {
			return EncodedFork{}, err
		}
		var entry [8]byte
		if kind == 4 {
			binary.LittleEndian.PutUint32(entry[:4], uint32(offset-260))
			binary.LittleEndian.PutUint32(entry[4:], uint32(len(encoded)))
		} else {
			binary.LittleEndian.PutUint32(entry[:4], uint32(offset))
		}
		if err = write(entry[:width], int64(base+block*width)); err != nil {
			return EncodedFork{}, err
		}
		offset += int64(len(encoded))
	}
	if kind == 4 {
		// Native Resource Manager header and one cmpf resource-map entry.
		trailer := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 28, 0, 50, 0, 0, 'c', 'm', 'p', 'f', 0, 0, 0, 10, 0, 1, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0}
		if err := write(trailer, offset); err != nil {
			return EncodedFork{}, err
		}
		var header [16]byte
		binary.BigEndian.PutUint32(header[:4], 256)
		binary.BigEndian.PutUint32(header[4:8], uint32(offset))
		binary.BigEndian.PutUint32(header[8:12], uint32(offset-256))
		binary.BigEndian.PutUint32(header[12:], uint32(len(trailer)))
		if err := write(header[:], 0); err != nil {
			return EncodedFork{}, err
		}
		var index [8]byte
		binary.BigEndian.PutUint32(index[:4], uint32(offset-260))
		binary.LittleEndian.PutUint32(index[4:], uint32(blocks))
		if err := write(index[:], 256); err != nil {
			return EncodedFork{}, err
		}
		offset += int64(len(trailer))
	} else {
		var end [4]byte
		binary.LittleEndian.PutUint32(end[:], uint32(offset))
		if err := write(end[:], int64(blocks*4)); err != nil {
			return EncodedFork{}, err
		}
	}
	return EncodedFork{Attribute: encodedHeader(kind, size), Size: offset}, nil
}

func encodedHeader(kind uint32, size int64) (header [HeaderSize]byte) {
	copy(header[:4], HeaderSignature[:])
	binary.LittleEndian.PutUint32(header[4:8], kind)
	binary.LittleEndian.PutUint64(header[8:], uint64(size))
	return header
}
func encodeBlock(plain []byte, kind uint32) ([]byte, error) {
	var encoded []byte
	marker := byte(0xff)
	switch kind {
	case 4:
		encoded = encodeZlibBlock(plain)
	case 8:
		buffer := make([]byte, len(plain))
		encoded = buffer[:lzfse.EncodeLZVNBuffer(buffer, plain)]
		marker = 0x06
	case 10:
		marker = 0xcc
	case 12:
		buffer := make([]byte, len(plain))
		encoded = buffer[:lzfse.EncodeBuffer(buffer, plain)]
	case 14:
		buffer := make([]byte, len(plain))
		encoded = buffer[:lzbitmap.EncodeBuffer(buffer, plain)]
	default:
		return nil, fmt.Errorf("unsupported compression type %d", kind)
	}
	if len(encoded) == 0 || kind == 4 && len(plain) != 1 && len(encoded) >= len(plain) {
		encoded = make([]byte, len(plain)+1)
		encoded[0] = marker
		copy(encoded[1:], plain)
	}
	return encoded, nil
}

// Native block tables have 32-bit offsets even when the logical file is larger.
// Check before writing, so a block cannot leave an unrepresentable table entry.
func checkEncodedExtent(offset, length int64) error {
	if offset < 0 || length < 0 || offset > math.MaxUint32 || length > math.MaxUint32-offset {
		return fmt.Errorf("compression payload exceeds native 32-bit offsets")
	}
	return nil
}
