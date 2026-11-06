// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2015-2016, Apple Inc. All rights reserved.
// Copyright (c) 2026 Deployment Theory.
//
// Finite State Entropy coding, after Apple's reference implementation
// (lzfse_fse.h, lzfse_fse.c). See LICENSE in this directory.

package lzfse

import (
	"encoding/binary"
	"math/bits"
)

// FSE is Jarek Duda's tANS: each stream symbol is coded by a state machine
// whose tables are built from a normalised frequency histogram.

// outStream accumulates bits for an FSE-coded stream written forwards.
// accumNBits is in [0, 64] while pushing and in [-7, 0] once finished.
type outStream struct {
	accum      uint64
	accumNBits int32
}

// push appends the n low bits b. The caller flushes before 64 bits overflow.
func (s *outStream) push(n int32, b uint64) {
	s.accum |= b << uint(s.accumNBits)
	s.accumNBits += n
}

// flush writes the accumulator's whole bytes to buf at *pos, leaving 0-7 bits.
// Like the reference it stores all 8 bytes and advances only past the whole
// ones; the slop is overwritten by the next flush.
func (s *outStream) flush(buf []byte, pos *int) {
	nbits := s.accumNBits &^ 7
	binary.LittleEndian.PutUint64(buf[*pos:], s.accum)
	*pos += int(nbits >> 3)
	s.accum >>= uint(nbits)
	s.accumNBits -= nbits
}

// finish writes the remaining bits, zero-padded to a byte, leaving
// accumNBits in [-7, 0]: minus the number of padding bits.
func (s *outStream) finish(buf []byte, pos *int) {
	nbits := (s.accumNBits + 7) &^ 7
	binary.LittleEndian.PutUint64(buf[*pos:], s.accum)
	*pos += int(nbits >> 3)
	s.accum = 0
	s.accumNBits -= nbits
}

// inStream reads an FSE-coded stream backwards, from the end of its payload
// towards its start, holding 56 to 63 bits between refills.
type inStream struct {
	accum      uint64
	accumNBits int32
}

// init primes the stream from the bytes ending at *pos, which must not move
// below start. n is the encoder's final accumNBits, in [-7, 0].
func (s *inStream) init(n int32, src []byte, pos *int, start int) bool {
	if n != 0 {
		if *pos < start+8 {
			return false
		}
		*pos -= 8
		s.accum = binary.LittleEndian.Uint64(src[*pos:])
		s.accumNBits = n + 64
	} else {
		if *pos < start+7 {
			return false
		}
		*pos -= 7
		s.accum = uint64(binary.LittleEndian.Uint32(src[*pos:])) |
			uint64(binary.LittleEndian.Uint16(src[*pos+4:]))<<32 |
			uint64(src[*pos+6])<<48
		s.accumNBits = n + 56
	}
	// The encoder zeroes the bits above those it wrote; anything else is a
	// corrupt stream.
	return s.accumNBits >= 56 && s.accumNBits < 64 && s.accum>>uint(s.accumNBits) == 0
}

// flush refills the accumulator to 56-63 bits from the bytes before *pos.
func (s *inStream) flush(src []byte, pos *int, start int) bool {
	nbits := (63 - s.accumNBits) &^ 7
	p := *pos - int(nbits>>3)
	if p < start {
		return false
	}
	*pos = p
	// The reference loads 8 bytes here. Near the start of the buffer fewer may
	// exist past p, but only the low nbits are kept, so read what is there.
	var incoming uint64
	if p+8 <= len(src) {
		incoming = binary.LittleEndian.Uint64(src[p:])
	} else {
		var tmp [8]byte
		copy(tmp[:], src[p:])
		incoming = binary.LittleEndian.Uint64(tmp[:])
	}
	s.accum = s.accum<<uint(nbits) | maskLSB64(incoming, nbits)
	s.accumNBits += nbits
	return true
}

// pull removes and returns the top n bits.
func (s *inStream) pull(n int32) uint64 {
	s.accumNBits -= n
	result := s.accum >> uint(s.accumNBits)
	s.accum = maskLSB64(s.accum, s.accumNBits)
	return result
}

// maskLSB64 keeps the low n bits of x, for n in [0, 64].
func maskLSB64(x uint64, n int32) uint64 {
	if n >= 64 {
		return x
	}
	return x & (1<<uint(n) - 1)
}

// encoderEntry is one symbol's row of an FSE encoder table.
type encoderEntry struct {
	s0     int16 // first state requiring a k-bit shift
	k      int16 // states >= s0 shift k bits, states below shift k-1
	delta0 int16 // next-state increment for states >= s0
	delta1 int16 // next-state increment for states < s0
}

// decoderEntry is one state's row of an FSE symbol decoder table.
type decoderEntry struct {
	k      int8  // bits to read
	symbol uint8 // symbol emitted
	delta  int16 // next-state base
}

// valueDecoderEntry is one state's row of an FSE value decoder table: the
// symbol is a base value plus valueBits extra bits read with the state bits.
type valueDecoderEntry struct {
	totalBits uint8 // state bits + value bits
	valueBits uint8 // extra value bits
	delta     int16 // next-state base
	vbase     int32 // value base
}

// encode writes symbol from state *state.
func fseEncode(state *uint16, table []encoderEntry, out *outStream, symbol uint8) {
	s := int(*state)
	e := table[symbol]
	nbits := int32(e.k)
	delta := e.delta0
	if s < int(e.s0) {
		nbits--
		delta = e.delta1
	}
	out.push(nbits, maskLSB64(uint64(s), nbits))
	*state = uint16(int(delta) + s>>uint(nbits))
}

// decode reads one symbol at state *state.
func fseDecode(state *uint16, table []decoderEntry, in *inStream) uint8 {
	e := table[*state]
	*state = uint16(e.delta) + uint16(in.pull(int32(e.k)))
	return e.symbol
}

// valueDecode reads one base+extra-bits value at state *state.
func fseValueDecode(state *uint16, table []valueDecoderEntry, in *inStream) int32 {
	e := table[*state]
	stateAndValueBits := uint32(in.pull(int32(e.totalBits)))
	*state = uint16(int32(e.delta) + int32(stateAndValueBits>>e.valueBits))
	return e.vbase + int32(maskLSB64(uint64(stateAndValueBits), int32(e.valueBits)))
}

// clz32 counts leading zero bits, as __builtin_clz.
func clz32(x uint32) int { return bits.LeadingZeros32(x) }

// checkFreq reports whether a frequency table's sum fits nstates.
func checkFreq(freq []uint16, nstates int) bool {
	sum := 0
	for _, f := range freq {
		sum += int(f)
	}
	return sum <= nstates
}

// initEncoderTable builds an encoder table from a normalised histogram whose
// sum is nstates, a power of two.
func initEncoderTable(nstates int, freq []uint16, t []encoderEntry) {
	offset := 0
	nclz := clz32(uint32(nstates))
	for i, fv := range freq {
		f := int(fv)
		if f == 0 {
			continue
		}
		k := clz32(uint32(f)) - nclz // so that nstates <= f<<k < 2*nstates
		t[i] = encoderEntry{
			s0:     int16(f<<uint(k) - nstates),
			k:      int16(k),
			delta0: int16(offset - f + nstates>>uint(k)),
			delta1: int16(offset - f + nstates>>uint(k-1)),
		}
		offset += f
	}
}

// initDecoderTable builds a symbol decoder table, or reports false when the
// frequencies overrun nstates.
func initDecoderTable(nstates int, freq []uint16, t []decoderEntry) bool {
	nclz := clz32(uint32(nstates))
	sum := 0
	n := 0
	for i, fv := range freq {
		f := int(fv)
		if f == 0 {
			continue
		}
		sum += f
		if sum > nstates {
			return false
		}
		k := clz32(uint32(f)) - nclz
		j0 := (2*nstates)>>uint(k) - f
		for j := range f {
			if j < j0 {
				t[n] = decoderEntry{k: int8(k), symbol: uint8(i), delta: int16((f+j)<<uint(k) - nstates)}
			} else {
				t[n] = decoderEntry{k: int8(k - 1), symbol: uint8(i), delta: int16((j - j0) << uint(k-1))}
			}
			n++
		}
	}
	return true
}

// initValueDecoderTable builds a value decoder table. The caller has checked
// the frequencies fit nstates.
func initValueDecoderTable(nstates int, freq []uint16, vbits []uint8, vbase []int32, t []valueDecoderEntry) {
	nclz := clz32(uint32(nstates))
	n := 0
	for i, fv := range freq {
		f := int(fv)
		if f == 0 {
			continue
		}
		k := clz32(uint32(f)) - nclz
		j0 := (2*nstates)>>uint(k) - f
		for j := range f {
			e := valueDecoderEntry{valueBits: vbits[i], vbase: vbase[i]}
			if j < j0 {
				e.totalBits = uint8(k) + e.valueBits
				e.delta = int16((f+j)<<uint(k) - nstates)
			} else {
				e.totalBits = uint8(k-1) + e.valueBits
				e.delta = int16((j - j0) << uint(k-1))
			}
			t[n] = e
			n++
		}
	}
}

// adjustFreqs removes overrun states from the symbols, largest share first.
func adjustFreqs(freq []uint16, overrun int) {
	// Every used symbol keeps at least one state and there are never more
	// symbols than states, so shift 0 always clears the overrun; the bound only
	// guards against a table that breaks that.
	for shift := 3; overrun != 0 && shift >= 0; shift-- {
		for sym := range freq {
			if freq[sym] > 1 {
				n := (int(freq[sym]) - 1) >> uint(shift)
				if n > overrun {
					n = overrun
				}
				freq[sym] -= uint16(n)
				overrun -= n
				if overrun == 0 {
					break
				}
			}
		}
	}
}

// normalizeFreq scales occurrence counts t to a histogram summing to nstates.
// The arithmetic is the reference's, 32-bit wraparound included, so the same
// counts give the same table.
func normalizeFreq(nstates int, t []uint32, freq []uint16) {
	var sCount uint32
	remaining := nstates
	maxFreq, maxFreqSym := 0, 0
	shift := uint(clz32(uint32(nstates)) - 1)
	for _, c := range t {
		sCount += c
	}
	var highprecStep uint32
	if sCount != 0 {
		highprecStep = (uint32(1) << 31) / sCount
	}
	for i, c := range t {
		// Round to nearest, in integer arithmetic.
		f := int(((c*highprecStep)>>shift + 1) >> 1)
		// A symbol that occurs must be representable.
		if f == 0 && c != 0 {
			f = 1
		}
		freq[i] = uint16(f)
		remaining -= f
		if f > maxFreq {
			maxFreq = f
			maxFreqSym = i
		}
	}
	// Give spare states to the most frequent symbol; take a small overrun from
	// it too, and spread a large one.
	if -remaining < maxFreq>>2 {
		freq[maxFreqSym] = uint16(int(freq[maxFreqSym]) + remaining)
	} else {
		adjustFreqs(freq, -remaining)
	}
}
