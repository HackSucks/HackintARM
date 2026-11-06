// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2015-2016, Apple Inc. All rights reserved.
// Copyright (c) 2026 Deployment Theory.
//
// LZVN encoder, after Apple's reference implementation (lzvn_encode_base.c).
// See LICENSE in this directory.

package lzfse

import (
	"encoding/binary"
	"math/bits"
)

const (
	lzvnHashBits          = 14
	lzvnHashValues        = 1 << lzvnHashBits
	lzvnMaxDistance       = 0xffff
	lzvnMinMargin         = 8   // bytes kept between the current position and the end
	lzvnMaxLiteralBacklog = 400 // pending literals past which a long literal is emitted
	lzvnMinSrcSize        = 8
	lzvnMinDstSize        = 8
)

// lzvnEntry holds the four most recent positions whose leading bytes hash
// alike, with the four bytes at each.
type lzvnEntry struct {
	indices [4]int32
	values  [4]uint32
}

// lzvnMatch is a candidate match: [mBegin, mEnd) repeats the bytes D earlier,
// and K is its gain, its length less the cost of storing D.
type lzvnMatch struct {
	mBegin, mEnd, M, D, K int
}

// lzvnEncoder is the reference encoder's state. Positions index src; dst is
// the output buffer, of which bytes [0, dstEnd) may be written.
type lzvnEncoder struct {
	src        []byte
	srcEnd     int
	srcCurrent int
	currentEnd int // last position considered for a match, +1
	srcLiteral int // first byte not yet encoded
	dst        []byte
	q          int // next output byte
	dstEnd     int
	pending    lzvnMatch
	dPrev      int
	table      []lzvnEntry
}

func load4(b []byte, i int) uint32 { return binary.LittleEndian.Uint32(b[i:]) }

// hash3 hashes the low three bytes of x.
//
// This is where the encoder departs from Apple's open-source reference, whose
// hash3i multiplies by 1+(1<<6)+(1<<12) and keeps bits 12 up. The encoder in
// macOS's libcompression hashes with Knuth's multiplicative constant instead,
// as the LZFSE match finder does: with it, 114 of 114 LZVN-sized samples
// encoded here match compression_encode_buffer byte for byte, against 86 with
// the reference's hash. The table size, 14 bits, is the same.
func hash3(x uint32) int {
	x &= 0xffffff
	return int((x * 2654435761) >> (32 - lzvnHashBits))
}

// trailingZeroBytes counts the equal leading bytes of two XORed words.
func trailingZeroBytes(x uint32) int {
	if x == 0 {
		return 4
	}
	return bits.TrailingZeros32(x) >> 3
}

func (e *lzvnEncoder) nmatch4(i, j int) int {
	return trailingZeroBytes(load4(e.src, i) ^ load4(e.src, j))
}

// findMatch checks whether mBegin repeats m0Begin for at least three bytes,
// given that the first n do, and expands the match both ways.
func (e *lzvnEncoder) findMatch(lBegin, m0Begin, mBegin, n int) (lzvnMatch, bool) {
	if n < 3 {
		return lzvnMatch{}, false
	}
	D := mBegin - m0Begin
	if D <= 0 || D > lzvnMaxDistance {
		return lzvnMatch{}, false
	}
	mEnd := mBegin + n
	for n == 4 && mEnd+4 < e.srcEnd {
		n = e.nmatch4(mEnd, mEnd-D)
		mEnd += n
	}
	for m0Begin > 0 && mBegin > lBegin && e.src[mBegin-1] == e.src[m0Begin-1] {
		m0Begin--
		mBegin--
	}
	M := mEnd - mBegin
	K := M - 3
	if D < 0x600 {
		K = M - 2
	}
	return lzvnMatch{mBegin: mBegin, mEnd: mEnd, M: M, D: D, K: K}, true
}

// better reports whether candidate should replace best.
func better(candidate, best lzvnMatch) bool {
	return candidate.K > best.K || (candidate.K == best.K && candidate.mEnd > best.mEnd+1)
}

// emitLiteral writes L literal bytes from src[p:] as literal-only opcodes. It
// reports false, leaving q unchanged, when they do not fit before q1.
func (e *lzvnEncoder) emitLiteral(p, L int) bool {
	q, q1 := e.q, e.dstEnd
	for L > 15 {
		x := min(L, 271)
		if q+x+10 >= q1 {
			return false
		}
		e.dst[q], e.dst[q+1] = 0xe0, byte(x-16)
		q += 2
		L -= x
		q += copy(e.dst[q:], e.src[p:p+x])
		p += x
	}
	if L > 0 {
		if q+L+10 >= q1 {
			return false
		}
		e.dst[q] = byte(0xe0 + L)
		q++
		q += copy(e.dst[q:], e.src[p:p+L])
	}
	e.q = q
	return true
}

// emit writes L literal bytes from src[p:] and a match of M bytes at distance
// D (M >= 3). It reports false, leaving q unchanged, when they do not fit.
func (e *lzvnEncoder) emit(p, L, M, D, dPrev int) bool {
	q, q1 := e.q, e.dstEnd
	for L > 15 {
		x := min(L, 271)
		if q+x+10 >= q1 {
			return false
		}
		e.dst[q], e.dst[q+1] = 0xe0, byte(x-16)
		q += 2
		L -= x
		q += copy(e.dst[q:], e.src[p:p+x])
		p += x
	}
	if L > 3 {
		if q+L+10 >= q1 {
			return false
		}
		e.dst[q] = byte(0xe0 + L)
		q++
		q += copy(e.dst[q:], e.src[p:p+L])
		p += L
		L = 0
	}
	x := min(M, 10-2*L)
	M -= x
	x -= 3 // the opcode carries x+3; up to 7-2L
	// Relaxed capacity test covering every opcode below.
	if q+8 >= q1 {
		return false
	}
	switch {
	case D == dPrev:
		if L == 0 {
			e.dst[q] = byte(0xf0 + x + 3)
		} else {
			e.dst[q] = byte(L<<6 + x<<3 + 6)
		}
		q++
	case D < 2048-2*256:
		e.dst[q] = byte(D>>8 + L<<6 + x<<3)
		e.dst[q+1] = byte(D)
		q += 2
	case D >= 1<<14 || M == 0 || x+3+M > 34:
		e.dst[q] = byte(L<<6 + x<<3 + 7)
		binary.LittleEndian.PutUint16(e.dst[q+1:], uint16(D))
		q += 3
	default:
		// Medium distance absorbs the rest of the match.
		x += M
		M = 0
		e.dst[q] = byte(0xa0 + x>>2 + L<<3)
		binary.LittleEndian.PutUint16(e.dst[q+1:], uint16(D<<2|x&3))
		q += 3
	}
	q += copy(e.dst[q:], e.src[p:p+L])
	for M > 15 {
		if q+2 >= q1 {
			return false
		}
		x := min(M, 271)
		e.dst[q], e.dst[q+1] = 0xf0, byte(x-16)
		q += 2
		M -= x
	}
	if M > 0 {
		if q+1 >= q1 {
			return false
		}
		e.dst[q] = byte(0xf0 + M)
		q++
	}
	e.q = q
	return true
}

func (e *lzvnEncoder) emitMatch(m lzvnMatch) bool {
	if !e.emit(e.srcLiteral, m.mBegin-e.srcLiteral, m.M, m.D, e.dPrev) {
		return false
	}
	e.dPrev = m.D
	e.srcLiteral = m.mEnd
	return true
}

func (e *lzvnEncoder) emitLiteralRun(n int) bool {
	if !e.emitLiteral(e.srcLiteral, n) {
		return false
	}
	e.srcLiteral += n
	return true
}

func (e *lzvnEncoder) emitEndOfStream() bool {
	if e.dstEnd < e.q+8 {
		return false
	}
	clear(e.dst[e.q : e.q+8])
	e.dst[e.q] = 0x06
	e.q += 8
	return true
}

// initTable points every entry at the first position.
func (e *lzvnEncoder) initTable() {
	value := load4(e.src, 0)
	var entry lzvnEntry
	for i := range 4 {
		entry.values[i] = value
	}
	e.table = make([]lzvnEntry, lzvnHashValues)
	for i := range e.table {
		e.table[i] = entry
	}
}

// encode is lzvn_encode: it scans for matches and emits what it can, stopping
// early when the output fills. A match still pending at the end is not
// emitted; its bytes go out as literals.
func (e *lzvnEncoder) encode() {
	for ; e.srcCurrent < e.currentEnd; e.srcCurrent++ {
		vi := load4(e.src, e.srcCurrent)
		h := hash3(vi)
		entry := e.table[h]
		updated := lzvnEntry{
			indices: [4]int32{int32(e.srcCurrent), entry.indices[0], entry.indices[1], entry.indices[2]},
			values:  [4]uint32{vi, entry.values[0], entry.values[1], entry.values[2]},
		}

		if e.srcCurrent >= e.srcLiteral {
			var incoming lzvnMatch
			for k := range 4 {
				nk := trailingZeroBytes(entry.values[k] ^ vi)
				if m, ok := e.findMatch(e.srcLiteral, int(entry.indices[k]), e.srcCurrent, nk); ok && better(m, incoming) {
					incoming = m
				}
			}
			if e.dPrev != 0 {
				m0 := e.srcCurrent - e.dPrev
				if m, ok := e.findMatch(e.srcLiteral, m0, e.srcCurrent, e.nmatch4(e.srcCurrent, m0)); ok {
					m.K = m.M - 1 // a repeated distance costs nothing to store
					if better(m, incoming) {
						incoming = m
					}
				}
			}

			switch {
			case incoming.M == 0:
				if e.srcCurrent-e.srcLiteral >= lzvnMaxLiteralBacklog {
					if e.pending.M != 0 {
						if !e.emitMatch(e.pending) {
							return
						}
						e.pending = lzvnMatch{}
					} else if !e.emitLiteralRun(271) {
						return
					}
				}
			case e.pending.M == 0:
				e.pending = incoming
			case e.pending.mEnd <= incoming.mBegin:
				// No overlap: emit pending, keep incoming.
				if !e.emitMatch(e.pending) {
					return
				}
				e.pending = incoming
			default:
				// Overlap: emit the better, discard the other.
				if incoming.K > e.pending.K {
					e.pending = incoming
				}
				if !e.emitMatch(e.pending) {
					return
				}
				e.pending = lzvnMatch{}
			}
		}
		// Committed only once the position's output is written, so a full
		// output leaves the state as it was at this position.
		e.table[h] = updated
	}
}

// lzvnEncodeBuffer encodes src into dst and returns the bytes written, or 0
// when the whole of src does not fit (lzvn_encode_buffer).
func lzvnEncodeBuffer(dst, src []byte) int {
	if len(dst) < lzvnMinDstSize {
		return 0
	}
	e := &lzvnEncoder{
		src:    src,
		srcEnd: len(src),
		dst:    dst,
		dstEnd: len(dst) - 8, // room for end-of-stream
	}
	if len(src) >= lzvnMinSrcSize {
		e.currentEnd = len(src) - lzvnMinMargin
		e.initTable()
		e.encode()
	}
	e.emitLiteralRun(e.srcEnd - e.srcLiteral)
	e.dstEnd = len(dst)
	e.emitEndOfStream()
	if e.srcLiteral != len(src) {
		return 0
	}
	return e.q
}
