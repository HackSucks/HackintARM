// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2015-2016, Apple Inc. All rights reserved.
// Copyright (c) 2026 Deployment Theory.
//
// LZFSE decoder, after Apple's reference implementation (lzfse_decode_base.c).
// See LICENSE in this directory.

package lzfse

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrCorrupt reports a stream the reference decoder would reject.
var ErrCorrupt = errors.New("lzfse: corrupt stream")

// ErrTruncated reports a stream that ends before its end-of-stream block.
var ErrTruncated = errors.New("lzfse: truncated stream")

// ErrOutputFull reports a stream that decodes to more bytes than allowed.
var ErrOutputFull = errors.New("lzfse: output exceeds limit")

func corrupt(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, args...))
}

// v1Header is lzfse_compressed_block_header_v1, the form both LZFSE block
// versions are decoded to.
type v1Header struct {
	nRawBytes            uint32
	nPayloadBytes        uint32
	nLiterals            uint32
	nMatches             uint32
	nLiteralPayloadBytes uint32
	nLMDPayloadBytes     uint32
	literalBits          int32
	literalState         [4]uint16
	lmdBits              int32
	lState, mState       uint16
	dState               uint16
	lFreq                [lSymbols]uint16
	mFreq                [mSymbols]uint16
	dFreq                [dSymbols]uint16
	literalFreq          [literalSymbols]uint16
}

// freqTables returns the header's four tables in stream order, which is how
// both header encodings serialise them.
func (h *v1Header) freqTables() [4][]uint16 {
	return [4][]uint16{h.lFreq[:], h.mFreq[:], h.dFreq[:], h.literalFreq[:]}
}

// check is lzfse_check_block_header_v1: every field within its range and every
// table summing to no more than its states.
func (h *v1Header) check() error {
	switch {
	case h.nLiterals > literalsPerBlock:
		return corrupt("%d literals in one block", h.nLiterals)
	case h.nMatches > matchesPerBlock:
		return corrupt("%d matches in one block", h.nMatches)
	case h.lState >= lStates || h.mState >= mStates || h.dState >= dStates:
		return corrupt("L, M or D state out of range")
	}
	for _, s := range h.literalState {
		if s >= literalStates {
			return corrupt("literal state %d out of range", s)
		}
	}
	if !checkFreq(h.lFreq[:], lStates) || !checkFreq(h.mFreq[:], mStates) ||
		!checkFreq(h.dFreq[:], dStates) || !checkFreq(h.literalFreq[:], literalStates) {
		return corrupt("frequency table overruns its states")
	}
	return nil
}

// freqNBits and freqValue decode a V2 header's frequency entries: a fixed
// Huffman code read LSB first, whose low five bits give its length.
var (
	freqNBits = [32]int8{
		2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
		2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
	}
	freqValue = [32]int8{
		0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1,
		0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1,
	}
)

func decodeFreqValue(bits uint32) (value uint16, nbits int) {
	b := bits & 31
	n := int(freqNBits[b])
	switch n {
	case 8:
		return uint16(8 + (bits>>4)&0xf), n
	case 14:
		return uint16(24 + (bits>>4)&0x3ff), n
	}
	return uint16(freqValue[b]), n
}

// field extracts nbits bits of v at offset.
func field(v uint64, offset, nbits uint) uint32 {
	if nbits == 32 {
		return uint32(v >> offset)
	}
	return uint32((v >> offset) & (1<<nbits - 1))
}

// decodeV2Header expands a V2 header (which begins at src[0]) to a V1 header.
func decodeV2Header(src []byte) (*v1Header, error) {
	v0 := binary.LittleEndian.Uint64(src[8:])
	v1 := binary.LittleEndian.Uint64(src[16:])
	v2 := binary.LittleEndian.Uint64(src[24:])
	h := &v1Header{
		nRawBytes:            binary.LittleEndian.Uint32(src[4:]),
		nLiterals:            field(v0, 0, 20),
		nLiteralPayloadBytes: field(v0, 20, 20),
		nMatches:             field(v0, 40, 20),
		literalBits:          int32(field(v0, 60, 3)) - 7,
		lmdBits:              int32(field(v1, 60, 3)) - 7,
		nLMDPayloadBytes:     field(v1, 40, 20),
		lState:               uint16(field(v2, 32, 10)),
		mState:               uint16(field(v2, 42, 10)),
		dState:               uint16(field(v2, 52, 10)),
	}
	for i := range h.literalState {
		h.literalState[i] = uint16(field(v1, uint(10*i), 10))
	}
	h.nPayloadBytes = h.nLiteralPayloadBytes + h.nLMDPayloadBytes

	headerSize := int(field(v2, 0, 32))
	if headerSize == v2FixedSize {
		return h, nil // tables omitted: all zero
	}
	pos, end := v2FixedSize, headerSize
	var accum uint32
	accumNBits := 0
	for _, table := range h.freqTables() {
		for i := range table {
			for pos < end && accumNBits+8 <= 32 {
				accum |= uint32(src[pos]) << uint(accumNBits)
				accumNBits += 8
				pos++
			}
			value, nbits := decodeFreqValue(accum)
			if nbits > accumNBits {
				return nil, corrupt("frequency table runs past its header")
			}
			table[i] = value
			accum >>= uint(nbits)
			accumNBits -= nbits
		}
	}
	// The tables must end exactly at the header's end.
	if accumNBits >= 8 || pos != end {
		return nil, corrupt("frequency tables do not fill their header")
	}
	return h, nil
}

// decodeV1Header reads an uncompressed-table header.
func decodeV1Header(src []byte) *v1Header {
	le := binary.LittleEndian
	h := &v1Header{
		nRawBytes:            le.Uint32(src[4:]),
		nPayloadBytes:        le.Uint32(src[8:]),
		nLiterals:            le.Uint32(src[12:]),
		nMatches:             le.Uint32(src[16:]),
		nLiteralPayloadBytes: le.Uint32(src[20:]),
		nLMDPayloadBytes:     le.Uint32(src[24:]),
		literalBits:          int32(le.Uint32(src[28:])),
		lmdBits:              int32(le.Uint32(src[40:])),
		lState:               le.Uint16(src[44:]),
		mState:               le.Uint16(src[46:]),
		dState:               le.Uint16(src[48:]),
	}
	for i := range h.literalState {
		h.literalState[i] = le.Uint16(src[32+2*i:])
	}
	off := 50
	for _, table := range h.freqTables() {
		for i := range table {
			table[i] = le.Uint16(src[off:])
			off += 2
		}
	}
	return h
}

// decoder decodes a whole stream into dst. Unlike the reference it is not
// resumable: the output buffer is sized up front, so a stream that does not
// fit is an error rather than a request for more room.
type decoder struct {
	src []byte
	dst []byte
	n   int // bytes written to dst

	// literals is shared by every LZFSE block, as the reference's is: a
	// malformed length that reads past one block's literals sees the previous
	// block's, not zeros.
	literals []byte
}

// decode runs the stream to its end-of-stream block.
func (d *decoder) decode() error {
	pos := 0
	for {
		if pos+4 > len(d.src) {
			return ErrTruncated
		}
		switch magic := binary.LittleEndian.Uint32(d.src[pos:]); magic {
		case magicEndOfStream:
			return nil
		case magicRaw:
			if pos+rawHeaderSize > len(d.src) {
				return ErrTruncated
			}
			n := int(binary.LittleEndian.Uint32(d.src[pos+4:]))
			pos += rawHeaderSize
			if n > len(d.src)-pos {
				return ErrTruncated
			}
			if n > len(d.dst)-d.n {
				return ErrOutputFull
			}
			d.n += copy(d.dst[d.n:], d.src[pos:pos+n])
			pos += n
		case magicLZVN:
			if pos+lzvnHeaderSize > len(d.src) {
				return ErrTruncated
			}
			nRaw := int(binary.LittleEndian.Uint32(d.src[pos+4:]))
			nPayload := int(binary.LittleEndian.Uint32(d.src[pos+8:]))
			pos += lzvnHeaderSize
			if nPayload > len(d.src)-pos {
				return ErrTruncated
			}
			if nRaw > len(d.dst)-d.n {
				return ErrOutputFull
			}
			// The block decodes into the shared output, so its matches may
			// reach back into earlier blocks.
			v := lzvnDecoder{src: d.src[pos : pos+nPayload], dst: d.dst[:d.n+nRaw], out: d.n}
			v.decode()
			if v.in != nPayload || v.out != d.n+nRaw || !v.endOfStream {
				return corrupt("LZVN block does not decode to its declared size")
			}
			d.n = v.out
			pos += nPayload
		case magicV1, magicV2:
			var h *v1Header
			var headerSize int
			if magic == magicV2 {
				if pos+v2FixedSize > len(d.src) {
					return ErrTruncated
				}
				headerSize = int(binary.LittleEndian.Uint32(d.src[pos+24:]))
				if headerSize < v2FixedSize {
					return corrupt("V2 header size %d", headerSize)
				}
				if headerSize > len(d.src)-pos {
					return ErrTruncated
				}
				var err error
				if h, err = decodeV2Header(d.src[pos : pos+headerSize]); err != nil {
					return err
				}
			} else {
				if pos+v1HeaderSize > len(d.src) {
					return ErrTruncated
				}
				headerSize = v1HeaderSize
				h = decodeV1Header(d.src[pos:])
			}
			if uint64(headerSize)+uint64(h.nLiteralPayloadBytes)+uint64(h.nLMDPayloadBytes) > uint64(len(d.src)-pos) {
				return ErrTruncated
			}
			if err := h.check(); err != nil {
				return err
			}
			pos += headerSize
			if err := d.decodeLZFSEBlock(h, pos); err != nil {
				return err
			}
			pos += int(h.nLiteralPayloadBytes) + int(h.nLMDPayloadBytes)
		default:
			return corrupt("unknown block magic %#08x", magic)
		}
	}
}

// decodeLZFSEBlock decodes one LZFSE block whose payload starts at pos.
func (d *decoder) decodeLZFSEBlock(h *v1Header, pos int) error {
	var (
		literalDecoder [literalStates]decoderEntry
		lDecoder       [lStates]valueDecoderEntry
		mDecoder       [mStates]valueDecoderEntry
		dDecoder       [dStates]valueDecoderEntry
	)
	// check has already bounded the sums; the literal table repeats it.
	if !initDecoderTable(literalStates, h.literalFreq[:], literalDecoder[:]) {
		return corrupt("literal frequency table overruns its states")
	}
	initValueDecoderTable(lStates, h.lFreq[:], lExtraBits[:], lBaseValue[:], lDecoder[:])
	initValueDecoderTable(mStates, h.mFreq[:], mExtraBits[:], mBaseValue[:], mDecoder[:])
	initValueDecoderTable(dStates, h.dFreq[:], dExtraBits[:], dBaseValue[:], dDecoder[:])

	// Literals: four interleaved FSE streams, read backwards from the end of
	// the literal payload. The buffer's floor is the start of the whole source,
	// as in the reference.
	if d.literals == nil {
		d.literals = make([]byte, literalsPerBlock+64)
	}
	literals := d.literals
	{
		var in inStream
		buf := pos + int(h.nLiteralPayloadBytes)
		if !in.init(h.literalBits, d.src, &buf, 0) {
			return corrupt("literal stream header")
		}
		state := h.literalState
		for i := uint32(0); i < h.nLiterals; i += 4 {
			if !in.flush(d.src, &buf, 0) {
				return corrupt("literal stream underruns its payload")
			}
			literals[i+0] = fseDecode(&state[0], literalDecoder[:], &in)
			literals[i+1] = fseDecode(&state[1], literalDecoder[:], &in)
			literals[i+2] = fseDecode(&state[2], literalDecoder[:], &in)
			literals[i+3] = fseDecode(&state[3], literalDecoder[:], &in)
		}
	}

	// L, M, D triples, read backwards from the end of the LMD payload, whose
	// floor is the payload's own start.
	lmdStart := pos + int(h.nLiteralPayloadBytes)
	buf := lmdStart + int(h.nLMDPayloadBytes)
	var in inStream
	if !in.init(h.lmdBits, d.src, &buf, lmdStart) {
		return corrupt("LMD stream header")
	}
	lState, mState, dState := h.lState, h.mState, h.dState
	lit := 0
	// D starts illegal so a first "repeat the previous distance" is caught.
	D := int32(-1)
	for range h.nMatches {
		if !in.flush(d.src, &buf, lmdStart) {
			return corrupt("LMD stream underruns its payload")
		}
		L := fseValueDecode(&lState, lDecoder[:], &in)
		if lit+int(L) >= literalsPerBlock+64 {
			return corrupt("literal length %d runs past the block's literals", L)
		}
		M := fseValueDecode(&mState, mDecoder[:], &in)
		if newD := fseValueDecode(&dState, dDecoder[:], &in); newD != 0 {
			D = newD
		}
		// A match may not reach before the start of the output, even one
		// of length zero: the reference checks D before it looks at M.
		if uint32(D) > uint32(d.n+int(L)) {
			return corrupt("match distance %d reaches before the start of the output", D)
		}
		if int(L)+int(M) > len(d.dst)-d.n {
			return ErrOutputFull
		}
		d.n += copy(d.dst[d.n:], literals[lit:lit+int(L)])
		lit += int(L)
		// Byte by byte: the source and destination overlap when D < M.
		for i := range int(M) {
			d.dst[d.n+i] = d.dst[d.n+i-int(D)]
		}
		d.n += int(M)
	}
	return nil
}
