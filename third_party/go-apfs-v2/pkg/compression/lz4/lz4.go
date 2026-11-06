// Package lz4 decodes Apple's framed LZ4 format in pure Go. Frames use bv41
// compressed blocks, bv4- stored blocks and a bv4$ terminator. Matches may
// refer to output from earlier blocks, as Apple's Compression API specifies.
package lz4

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var (
	ErrInvalid    = errors.New("invalid LZ4 stream")
	ErrTruncated  = errors.New("truncated LZ4 stream")
	ErrOutputFull = errors.New("LZ4 output exceeds destination")
)

// DecompressInto decodes one Apple frame into caller-owned dst. It returns
// decoded progress and an error on malformed input. Like Apple's buffer API,
// decoding stops when dst is full or a terminator is reached; bytes beyond that
// point are not validated. Input and output must not
// overlap, and callers must discard partial output when an error is returned.
func DecompressInto(dst, src []byte) (int, error) {
	return DecompressReader(dst, bytes.NewReader(src), int64(len(src)))
}

// DecompressReader decodes a known-size source through reads of at most 32 KiB.
// It never materializes the complete encoded range. The source remains borrowed
// and must stay unchanged until return. Only the supplied destination retains
// decoded bytes; no output-size-dependent internal allocation is made.
func DecompressReader(dst []byte, source io.ReaderAt, size int64) (written int, err error) {
	if source == nil || size < 0 {
		return 0, ErrInvalid
	}
	r := &cursor{reader: bufio.NewReaderSize(io.NewSectionReader(source, 0, size), 32<<10), remaining: size}
	var header [12]byte
	for {
		if written == len(dst) {
			return written, nil
		}
		if _, err = r.read(header[:4]); err != nil {
			return written, err
		}
		magic := string(header[:4])
		if magic == "bv4$" {
			return written, nil
		}
		if magic != "bv4-" && magic != "bv41" {
			return written, fmt.Errorf("%w: unknown block header", ErrInvalid)
		}
		if _, err = r.read(header[4:8]); err != nil {
			return written, err
		}
		plain := int64(binary.LittleEndian.Uint32(header[4:8]))
		end := int64(written) + plain
		if magic == "bv4-" {
			if plain > r.remaining {
				return written, ErrTruncated
			}
			var n int
			n, err = r.read(dst[written:min(end, int64(len(dst)))])
			written += n
			if err != nil {
				return written, err
			}
			continue
		}
		if _, err = r.read(header[8:12]); err != nil {
			return written, err
		}
		encoded := int64(binary.LittleEndian.Uint32(header[8:12]))
		if encoded > r.remaining {
			return written, ErrTruncated
		}
		block := &cursor{reader: r.reader, remaining: encoded}
		written, err = decodeBlock(dst, written, end, block)
		r.remaining -= encoded - block.remaining
		if err != nil {
			return written, err
		}
		if written == len(dst) {
			return written, nil
		}
		if int64(written) != end {
			return written, fmt.Errorf("%w: decoded block size mismatch", ErrInvalid)
		}
	}
}

type cursor struct {
	reader    *bufio.Reader
	remaining int64
}

func (r *cursor) read(p []byte) (int, error) {
	if int64(len(p)) > r.remaining {
		return 0, ErrTruncated
	}
	total := 0
	for total < len(p) {
		n, err := io.ReadFull(r.reader, p[total:min(total+32<<10, len(p))])
		total += n
		r.remaining -= int64(n)
		if err != nil {
			return total, errors.Join(ErrTruncated, err)
		}
	}
	return total, nil
}
func (r *cursor) byte() (byte, error) {
	if r.remaining == 0 {
		return 0, ErrTruncated
	}
	b, err := r.reader.ReadByte()
	if err != nil {
		return 0, errors.Join(ErrTruncated, err)
	}
	r.remaining--
	return b, nil
}

// Extended lengths are accumulated against the remaining output bound before
// addition, preventing overflow even for adversarial runs of 255 length bytes.
func length(r *cursor, base, limit int64) (int64, error) {
	if base > limit {
		return 0, ErrOutputFull
	}
	n := base
	if base != 15 {
		return n, nil
	}
	for {
		b, err := r.byte()
		if err != nil {
			return 0, err
		}
		if int64(b) > limit-n {
			return 0, ErrOutputFull
		}
		n += int64(b)
		if b != 255 {
			return n, nil
		}
	}
}
func decodeBlock(dst []byte, written int, end int64, r *cursor) (int, error) {
	for r.remaining > 0 {
		token, err := r.byte()
		if err != nil {
			return written, err
		}
		literals, err := length(r, int64(token>>4), end-int64(written))
		if err != nil {
			return written, err
		}
		if literals > r.remaining {
			return written, ErrTruncated
		}
		n, err := r.read(dst[written : written+int(min(literals, int64(len(dst)-written)))])
		written += n
		if err != nil {
			return written, err
		}
		if r.remaining == 0 || written == len(dst) {
			return written, nil
		}
		var offset [2]byte
		if _, err = r.read(offset[:]); err != nil {
			return written, err
		}
		distance := int(binary.LittleEndian.Uint16(offset[:]))
		if distance == 0 || distance > written {
			return written, fmt.Errorf("%w: match before history", ErrInvalid)
		}
		if end-int64(written) < 4 {
			return written, ErrOutputFull
		}
		match, err := length(r, int64(token&15), end-int64(written)-4)
		if err != nil {
			return written, err
		}
		match = min(match+4, int64(len(dst)-written))
		for match > 0 {
			n = copy(dst[written:written+int(match)], dst[written-distance:written])
			written += n
			match -= int64(n)
		}
		if written == len(dst) {
			return written, nil
		}
	}
	return written, nil
}
