// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2015-2016, Apple Inc. All rights reserved.
// Copyright (c) 2026 Deployment Theory.

// Package lzfse encodes and decodes Apple's LZFSE and LZVN compression
// formats in pure Go.
//
// It is a port of Apple's reference implementation (github.com/lzfse/lzfse,
// BSD-3-Clause; see LICENSE in this directory), and it follows that code
// rather than improving on it, because what matters is agreeing with macOS:
//
//   - The encoder makes the same choices as the reference -- the same matches,
//     the same block splits, the same frequency tables -- so for the same
//     input it writes the same bytes.
//   - The decoder rejects what the reference rejects. In particular it checks
//     every match distance against the output written so far, which is how
//     Apple's decoder refuses a stream whose encoder let a distance reach
//     before the start of the output. A lenient decoder here would hide
//     exactly that kind of encoder bug from a round-trip test.
//
// The package was written to replace github.com/go-compressions/lzfse, whose
// encoder could produce such streams: hdiutil then could not read a DMG that
// this module's own reader decoded without complaint.
package lzfse

import (
	"encoding/binary"
	"fmt"
)

// maxEncodeSize bounds the input Compress accepts. The reference encodes
// larger inputs in windows; nothing here needs that.
const maxEncodeSize = 1<<31 - 1 - 12

// Compress returns src as an LZFSE stream. It never expands the input by more
// than an uncompressed block's twelve bytes: when compression would, the data
// is stored uncompressed, as the reference encoder does given room for that.
func Compress(src []byte) ([]byte, error) {
	if len(src) > maxEncodeSize {
		return nil, fmt.Errorf("lzfse: %d-byte input exceeds %d", len(src), maxEncodeSize)
	}
	dst := make([]byte, len(src)+12)
	n := encodeBuffer(dst, src)
	if n == 0 {
		return nil, fmt.Errorf("lzfse: %d-byte input did not encode", len(src))
	}
	return dst[:n], nil
}

// EncodeBuffer encodes src into dst and returns the bytes written, or 0 when
// the stream does not fit. It is lzfse_encode_buffer: the output depends on
// len(dst), because the encoder falls back to an uncompressed block, and then
// to failure, as room runs out.
func EncodeBuffer(dst, src []byte) int {
	if len(src) > maxEncodeSize {
		return 0
	}
	return encodeBuffer(dst, src)
}

// DecodedSize returns how many bytes src decodes to, as its block headers
// declare, without decoding it.
func DecodedSize(src []byte) (int, error) {
	le := binary.LittleEndian
	var total uint64
	for pos := 0; ; {
		if pos+4 > len(src) {
			return 0, ErrTruncated
		}
		magic := le.Uint32(src[pos:])
		if magic == magicEndOfStream {
			if total > uint64(maxInt) {
				return 0, ErrOutputFull
			}
			return int(total), nil
		}
		if pos+8 > len(src) {
			return 0, ErrTruncated
		}
		total += uint64(le.Uint32(src[pos+4:]))
		var header, payload uint64
		switch magic {
		case magicRaw:
			header, payload = rawHeaderSize, uint64(le.Uint32(src[pos+4:]))
		case magicLZVN:
			if pos+lzvnHeaderSize > len(src) {
				return 0, ErrTruncated
			}
			header, payload = lzvnHeaderSize, uint64(le.Uint32(src[pos+8:]))
		case magicV1:
			if pos+v1HeaderSize > len(src) {
				return 0, ErrTruncated
			}
			header = v1HeaderSize
			payload = uint64(le.Uint32(src[pos+20:])) + uint64(le.Uint32(src[pos+24:]))
		case magicV2:
			if pos+v2FixedSize > len(src) {
				return 0, ErrTruncated
			}
			v0 := le.Uint64(src[pos+8:])
			v1 := le.Uint64(src[pos+16:])
			header = uint64(le.Uint32(src[pos+24:]))
			if header < v2FixedSize {
				return 0, corrupt("V2 header size %d", header)
			}
			payload = uint64(field(v0, 20, 20)) + uint64(field(v1, 40, 20))
		default:
			return 0, corrupt("unknown block magic %#08x", magic)
		}
		step := header + payload
		if step == 0 {
			return 0, corrupt("block does not advance")
		}
		if step > uint64(len(src)-pos) {
			return 0, ErrTruncated
		}
		pos += int(step)
	}
}

const maxInt = int(^uint(0) >> 1)

// Decompress decodes an LZFSE stream. Its output buffer is sized from the
// block headers (DecodedSize), so a stream that decodes to more than it
// declares is rejected rather than grown into.
// It allocates the size declared by the stream's headers. Callers handling
// untrusted input with a known output bound should use DecompressInto with
// a buffer of that size.
func Decompress(src []byte) ([]byte, error) {
	size, err := DecodedSize(src)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, size)
	n, err := DecompressInto(dst, src)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

// DecompressInto decodes an LZFSE stream into dst and returns the bytes
// written. It fails with ErrOutputFull when the stream decodes to more than
// len(dst) bytes.
func DecompressInto(dst, src []byte) (int, error) {
	d := decoder{src: src, dst: dst}
	if err := d.decode(); err != nil {
		return 0, err
	}
	return d.n, nil
}

// CompressLZVN returns src as a bare LZVN stream, without an LZFSE block
// header: the form decmpfs stores. Inputs shorter than eight bytes are all
// literals.
func CompressLZVN(src []byte) []byte {
	// Room for the worst case. Short matches in near-random data are the
	// costliest: fifteen literals and a three-byte match take nineteen bytes
	// for eighteen. The encoder also keeps a margin before the end.
	dst := make([]byte, len(src)+len(src)/16+64)
	n := lzvnEncodeBuffer(dst, src)
	return dst[:n]
}

// DecompressLZVN decodes a bare LZVN stream to at most size bytes. It succeeds
// when the stream reaches its end-of-stream opcode or fills size bytes.
func DecompressLZVN(src []byte, size int) ([]byte, error) {
	dst := make([]byte, size)
	v := lzvnDecoder{src: src, dst: dst}
	v.decode()
	if !v.endOfStream && v.out < size {
		return nil, corrupt("LZVN stream stops after %d of %d bytes", v.out, size)
	}
	return dst[:v.out], nil
}

// EncodeLZVNBuffer encodes using the native LZVN buffer contract. Inputs shorter
// than eight bytes and insufficient destination space return zero. On zero,
// destination contents are unspecified. Buffers must not overlap.
func EncodeLZVNBuffer(dst, src []byte) int {
	if len(src) < 8 {
		return 0
	}
	return lzvnEncodeBuffer(dst, src)
}
