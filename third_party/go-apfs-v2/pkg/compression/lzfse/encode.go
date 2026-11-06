// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2015-2016, Apple Inc. All rights reserved.
// Copyright (c) 2026 Deployment Theory.
//
// LZFSE encoder, after Apple's reference implementation (lzfse_encode.c,
// lzfse_encode_base.c). See LICENSE in this directory.

package lzfse

import (
	"encoding/binary"
	"math/bits"
)

// v2MaxHeaderSize is sizeof(lzfse_compressed_block_header_v2): the fixed part
// plus every table entry at its widest, two bytes.
const v2MaxHeaderSize = v2FixedSize + 2*(lSymbols+mSymbols+dSymbols+literalSymbols)

// outputSlack is room past an output buffer's capacity for the reference's
// wide stores, which may write up to eight bytes beyond the bytes they keep.
const outputSlack = 16

// historySet is one line of the match finder's hash table: the four most
// recent positions whose leading four bytes hash alike, with those bytes.
type historySet struct {
	pos   [encodeHashWidth]int32
	value [encodeHashWidth]uint32
}

// lzMatch is src[pos:pos+length] repeating src[ref:].
type lzMatch struct {
	pos, ref int
	length   int
}

// encoder is the reference encoder's state. dst is written up to dstEnd; the
// slice extends outputSlack further for slop.
type encoder struct {
	src          []byte
	srcEnd       int
	srcLiteral   int // first byte not yet pushed
	srcEncodeI   int // byte being matched
	srcEncodeEnd int

	dst    []byte
	q      int
	dstEnd int

	pending lzMatch

	nMatches  int
	nLiterals int
	lValues   [matchesPerBlock]uint32
	mValues   [matchesPerBlock]uint32
	dValues   [matchesPerBlock]uint32
	literals  [literalsPerBlock]byte

	history [encodeHashValues]historySet
}

func hashX(x uint32) uint32 { return (x * 2654435761) >> (32 - encodeHashBits) }

func newEncoder(dst, src []byte, dstEnd int) *encoder {
	e := &encoder{src: src, srcEnd: len(src), dst: dst, dstEnd: dstEnd}
	var line historySet
	for i := range line.pos {
		line.pos[i] = -4 * maxDValue // no position
	}
	for i := range e.history {
		e.history[i] = line
	}
	return e
}

// freqCode returns a table entry's fixed Huffman code and its length.
func freqCode(value int) (code uint32, nbits int) {
	switch value {
	case 0:
		return 0, 2
	case 1:
		return 2, 2
	case 2:
		return 1, 3
	case 3:
		return 5, 3
	case 4:
		return 3, 5
	case 5:
		return 11, 5
	case 6:
		return 19, 5
	case 7:
		return 27, 5
	}
	if value < 24 {
		return 7 + uint32(value-8)<<4, 8
	}
	return uint32(value-24)<<4 + 15, 14
}

// encodeMatches encodes the pushed matches and literals as one V2 block. It
// reports false, leaving the state as it was, when the block does not fit.
func (e *encoder) encodeMatches() bool {
	if e.nLiterals == 0 && e.nMatches == 0 {
		return true
	}
	q0, nLiterals0 := e.q, e.nLiterals

	// Four interleaved literal streams: pad to a multiple of four.
	for e.nLiterals&3 != 0 {
		e.literals[e.nLiterals] = 0
		e.nLiterals++
	}
	// A distance equal to the previous one is stored as 0.
	dPrev := uint32(0)
	for i := range e.nMatches {
		if d := e.dValues[i]; d == dPrev {
			e.dValues[i] = 0
		} else {
			dPrev = d
		}
	}
	restore := func() bool {
		dPrev := uint32(0)
		for i := range e.nMatches {
			if d := e.dValues[i]; d == 0 {
				e.dValues[i] = dPrev
			} else {
				dPrev = d
			}
		}
		e.nLiterals = nLiterals0
		e.q = q0
		return false
	}

	var (
		lOcc       [lSymbols]uint32
		mOcc       [mSymbols]uint32
		dOcc       [dSymbols]uint32
		literalOcc [literalSymbols]uint32
		lSum, mSum uint32
	)
	for i := range e.nMatches {
		lSum += e.lValues[i]
		lOcc[lSymbolOf[e.lValues[i]]]++
	}
	for i := range e.nMatches {
		mSum += e.mValues[i]
		mOcc[mSymbolOf[e.mValues[i]]]++
	}
	for i := range e.nMatches {
		dOcc[dSymbolOf[e.dValues[i]]]++
	}
	for _, b := range e.literals[:e.nLiterals] {
		literalOcc[b]++
	}

	// Room for a full-sized header, as the reference requires.
	if e.q+v2MaxHeaderSize > e.dstEnd {
		return restore()
	}
	header := e.q

	var h v1Header
	h.nRawBytes = mSum + lSum
	h.nMatches = uint32(e.nMatches)
	h.nLiterals = uint32(e.nLiterals)
	normalizeFreq(lStates, lOcc[:], h.lFreq[:])
	normalizeFreq(mStates, mOcc[:], h.mFreq[:])
	normalizeFreq(dStates, dOcc[:], h.dFreq[:])
	normalizeFreq(literalStates, literalOcc[:], h.literalFreq[:])

	// The frequency tables, as a bit stream after the fixed fields.
	p := header + v2FixedSize
	var accum uint32
	accumNBits := 0
	for _, table := range h.freqTables() {
		for _, f := range table {
			code, nbits := freqCode(int(f))
			accum |= code << uint(accumNBits)
			accumNBits += nbits
			for accumNBits >= 8 {
				e.dst[p] = byte(accum)
				p++
				accum >>= 8
				accumNBits -= 8
			}
		}
	}
	if accumNBits > 0 {
		e.dst[p] = byte(accum)
		p++
	}
	headerSize := p - header
	e.q = p

	var (
		lEncoder       [lSymbols]encoderEntry
		mEncoder       [mSymbols]encoderEntry
		dEncoder       [dSymbols]encoderEntry
		literalEncoder [literalSymbols]encoderEntry
	)
	initEncoderTable(lStates, h.lFreq[:], lEncoder[:])
	initEncoderTable(mStates, h.mFreq[:], mEncoder[:])
	initEncoderTable(dStates, h.dFreq[:], dEncoder[:])
	initEncoderTable(literalStates, h.literalFreq[:], literalEncoder[:])

	// Literals, last first, so the decoder reads them first to last.
	{
		var out outStream
		var state [4]uint16
		buf := e.q
		for i := e.nLiterals; i > 0; {
			if buf+16 > e.dstEnd {
				return restore()
			}
			i -= 4
			fseEncode(&state[3], literalEncoder[:], &out, e.literals[i+3])
			fseEncode(&state[2], literalEncoder[:], &out, e.literals[i+2])
			fseEncode(&state[1], literalEncoder[:], &out, e.literals[i+1])
			fseEncode(&state[0], literalEncoder[:], &out, e.literals[i+0])
			out.flush(e.dst, &buf)
		}
		out.finish(e.dst, &buf)
		h.literalBits = out.accumNBits
		h.nLiteralPayloadBytes = uint32(buf - e.q)
		h.literalState = state
		e.q = buf
	}

	// L, M, D, last first, after eight bytes of padding.
	{
		var out outStream
		var lState, mState, dState uint16
		buf := e.q
		if buf+8 > e.dstEnd {
			return restore()
		}
		clear(e.dst[buf : buf+8])
		buf += 8
		for i := e.nMatches; i > 0; {
			if buf+16 > e.dstEnd {
				return restore()
			}
			i--
			dValue := int32(e.dValues[i])
			dSymbol := dSymbolOf[dValue]
			out.push(int32(dExtraBits[dSymbol]), uint64(dValue-dBaseValue[dSymbol]))
			fseEncode(&dState, dEncoder[:], &out, dSymbol)

			mValue := int32(e.mValues[i])
			mSymbol := mSymbolOf[mValue]
			out.push(int32(mExtraBits[mSymbol]), uint64(mValue-mBaseValue[mSymbol]))
			fseEncode(&mState, mEncoder[:], &out, mSymbol)

			lValue := int32(e.lValues[i])
			lSymbol := lSymbolOf[lValue]
			out.push(int32(lExtraBits[lSymbol]), uint64(lValue-lBaseValue[lSymbol]))
			fseEncode(&lState, lEncoder[:], &out, lSymbol)
			out.flush(e.dst, &buf)
		}
		out.finish(e.dst, &buf)
		h.nLMDPayloadBytes = uint32(buf - e.q)
		h.lmdBits = out.accumNBits
		h.lState, h.mState, h.dState = lState, mState, dState
		e.q = buf
	}

	e.nLiterals = 0
	e.nMatches = 0

	// The fixed fields, now that the payload has set them.
	le := binary.LittleEndian
	le.PutUint32(e.dst[header:], magicV2)
	le.PutUint32(e.dst[header+4:], h.nRawBytes)
	le.PutUint64(e.dst[header+8:], uint64(h.nLiterals)|
		uint64(h.nLiteralPayloadBytes)<<20|
		uint64(h.nMatches)<<40|
		uint64(7+h.literalBits)<<60)
	le.PutUint64(e.dst[header+16:], uint64(h.literalState[0])|
		uint64(h.literalState[1])<<10|
		uint64(h.literalState[2])<<20|
		uint64(h.literalState[3])<<30|
		uint64(h.nLMDPayloadBytes)<<40|
		uint64(7+h.lmdBits)<<60)
	le.PutUint64(e.dst[header+24:], uint64(headerSize)|
		uint64(h.lState)<<32|
		uint64(h.mState)<<42|
		uint64(h.dState)<<52)
	return true
}

// pushLMD records one L, M, D triple and its L literals. It reports false,
// leaving the state unchanged, when the block's tables are full.
func (e *encoder) pushLMD(L, M, D int) bool {
	if e.nMatches+1+8 > matchesPerBlock {
		return false
	}
	if e.nLiterals+L+16 > literalsPerBlock {
		return false
	}
	n := e.nMatches
	e.nMatches++
	e.lValues[n] = uint32(L)
	e.mValues[n] = uint32(M)
	e.dValues[n] = uint32(D)
	copy(e.literals[e.nLiterals:], e.src[e.srcLiteral:e.srcLiteral+L])
	e.nLiterals += L
	e.srcLiteral += L + M
	return true
}

// pushMatch records a match as one or more triples, splitting a long literal
// run or a long match. It reports false, leaving the state unchanged, when
// the block's tables are full.
func (e *encoder) pushMatch(m lzMatch) bool {
	nMatches0, nLiterals0, srcLiteral0 := e.nMatches, e.nLiterals, e.srcLiteral
	fail := func() bool {
		e.nMatches, e.nLiterals, e.srcLiteral = nMatches0, nLiterals0, srcLiteral0
		return false
	}
	L := m.pos - e.srcLiteral
	M := m.length
	D := m.pos - m.ref

	// A literal run too long for one triple is split off with M=0. Its D is
	// 1, which is the most frequent distance and is never used for copying --
	// but a decoder still checks it against the output written so far, so it
	// must be 1 and not the match's own D, which can reach before the start.
	for L > maxLValue {
		if !e.pushLMD(maxLValue, 0, 1) {
			return fail()
		}
		L -= maxLValue
	}
	for M > maxMValue {
		if !e.pushLMD(L, maxMValue, D) {
			return fail()
		}
		L = 0
		M -= maxMValue
	}
	if L > 0 || M > 0 {
		if !e.pushLMD(L, M, D) {
			return fail()
		}
	}
	return true
}

// backendMatch adds a match, emitting a block first if the tables are full.
func (e *encoder) backendMatch(m lzMatch) bool {
	if e.pushMatch(m) {
		return true
	}
	if !e.encodeMatches() {
		return false
	}
	return e.pushMatch(m)
}

// backendLiterals adds L literals as a match of length zero at distance 1.
func (e *encoder) backendLiterals(L int) bool {
	pos := e.srcLiteral + L
	return e.backendMatch(lzMatch{pos: pos, ref: pos - 1})
}

// backendEndOfStream emits the last block and the end-of-stream marker.
func (e *encoder) backendEndOfStream() bool {
	if !e.encodeMatches() {
		return false
	}
	if e.q+4 > e.dstEnd {
		return false
	}
	binary.LittleEndian.PutUint32(e.dst[e.q:], magicEndOfStream)
	e.q += 4
	return true
}

// encodeBase is the match-finding front end (lzfse_encode_base). It reports
// false when the output fills.
func (e *encoder) encodeBase() bool {
	e.srcEncodeEnd = e.srcEnd - 8
	for ; e.srcEncodeI < e.srcEncodeEnd; e.srcEncodeI++ {
		pos := e.srcEncodeI
		x := load4(e.src, pos)
		line := &e.history[hashX(x)]
		h := *line
		newH := historySet{
			pos:   [4]int32{int32(pos), h.pos[0], h.pos[1], h.pos[2]},
			value: [4]uint32{x, h.value[0], h.value[1], h.value[2]},
		}

		if pos >= e.srcLiteral {
			if !e.consider(pos, x, h) {
				return false
			}
		}
		*line = newH
	}
	return true
}

// consider looks for a match at pos and feeds the backend. It reports false
// when the output fills.
func (e *encoder) consider(pos int, x uint32, h historySet) bool {
	incoming := lzMatch{pos: pos}
	for k := range encodeHashWidth {
		if h.value[k] != x {
			continue // no four-byte match
		}
		ref := int(h.pos[k])
		if ref+maxDValue < pos {
			continue // too far
		}
		length := 4
		maxLength := e.srcEnd - pos - 8
		for length < maxLength {
			d := binary.LittleEndian.Uint64(e.src[ref+length:]) ^ binary.LittleEndian.Uint64(e.src[pos+length:])
			if d == 0 {
				length += 8
				continue
			}
			length += bits.TrailingZeros64(d) >> 3
			break
		}
		if length > incoming.length {
			incoming.length = length
			incoming.ref = ref
		}
	}

	if incoming.length == 0 {
		// Keep the literal backlog well inside one block.
		if pos-e.srcLiteral > 8*maxLValue {
			if e.pending.length > 0 {
				if !e.backendMatch(e.pending) {
					return false
				}
				e.pending = lzMatch{}
			} else if !e.backendLiterals(maxLValue) {
				return false
			}
		}
		return true
	}

	incoming.length = min(incoming.length, maxMatchLength)
	// Extend the best match backwards.
	for incoming.pos > e.srcLiteral && incoming.ref > 0 && e.src[incoming.ref-1] == e.src[incoming.pos-1] {
		incoming.pos--
		incoming.ref--
	}
	incoming.length += pos - incoming.pos

	switch {
	case incoming.length >= encodeGoodMatch:
		// Good enough to emit at once.
		if !e.backendMatch(incoming) {
			return false
		}
		e.pending = lzMatch{}
	case e.pending.length == 0:
		e.pending = incoming
	case e.pending.pos+e.pending.length <= incoming.pos:
		// No overlap: emit pending, keep incoming.
		if !e.backendMatch(e.pending) {
			return false
		}
		e.pending = incoming
	default:
		// Overlap: emit the longer.
		m := e.pending
		if incoming.length > e.pending.length {
			m = incoming
		}
		if !e.backendMatch(m) {
			return false
		}
		e.pending = lzMatch{}
	}
	return true
}

// encodeFinish flushes the pending match and trailing literals, and ends the
// stream.
func (e *encoder) encodeFinish() bool {
	if e.pending.length > 0 {
		if !e.backendMatch(e.pending) {
			return false
		}
		e.pending = lzMatch{}
	}
	if L := e.srcEnd - e.srcLiteral; L > 0 {
		if !e.backendLiterals(L) {
			return false
		}
	}
	return e.backendEndOfStream()
}

// encodeBuffer encodes src into dst and returns the bytes written, or 0 when
// they do not fit (lzfse_encode_buffer).
func encodeBuffer(dst, src []byte) int {
	n := len(src)
	if n >= lzvnMinSrcSize && n < encodeLZVNThreshold {
		// Small inputs go to LZVN, inside a bvxn block.
		const extra = 4 + lzvnHeaderSize
		if len(dst) > extra {
			sz := lzvnEncodeBuffer(dst[lzvnHeaderSize:len(dst)-4], src)
			if sz != 0 && sz < n {
				le := binary.LittleEndian
				le.PutUint32(dst, magicLZVN)
				le.PutUint32(dst[4:], uint32(n))
				le.PutUint32(dst[8:], uint32(sz))
				le.PutUint32(dst[lzvnHeaderSize+sz:], magicEndOfStream)
				return sz + extra
			}
		}
	} else if n >= encodeLZVNThreshold && uint64(n) < 0xffffffff {
		// The reference encodes inputs of 4 GiB and more in 256 KiB windows;
		// this package's callers encode chunks far smaller than that, and
		// anything that large falls through to the uncompressed block.
		out := make([]byte, len(dst)+outputSlack)
		e := newEncoder(out, src, len(dst))
		if e.encodeBase() && e.encodeFinish() {
			return copy(dst, out[:e.q])
		}
	}

	// Uncompressed, when it fits.
	if n+12 <= len(dst) && n < 1<<31-1 {
		le := binary.LittleEndian
		le.PutUint32(dst, magicRaw)
		le.PutUint32(dst[4:], uint32(n))
		copy(dst[rawHeaderSize:], src)
		le.PutUint32(dst[rawHeaderSize+n:], magicEndOfStream)
		return n + 12
	}
	return 0
}
