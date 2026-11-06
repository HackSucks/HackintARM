// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2015-2016, Apple Inc. All rights reserved.
// Copyright (c) 2026 Deployment Theory.
//
// LZVN decoder, after Apple's reference implementation (lzvn_decode_base.c).
// See LICENSE in this directory.

package lzfse

import "encoding/binary"

// LZVN opcode classes, indexed by the opcode byte.
const (
	opSmallD      = iota // LLMMMDDD DDDDDDDD literal: small distance
	opMediumD            // 101LLMMM DDDDDDMM DDDDDDDD literal: medium distance
	opLargeD             // LLMMM111 DDDDDDDD DDDDDDDD literal: large distance
	opPrevD              // LLMMM110 literal: previous distance
	opSmallM             // 1111MMMM: match at previous distance
	opLargeM             // 11110000 MMMMMMMM: match at previous distance
	opSmallL             // 1110LLLL literal
	opLargeL             // 11100000 LLLLLLLL literal
	opNop                // 00001110, 00010110
	opEndOfStream        // 00000110 + 7 bytes
	opUndefined
)

// lzvnOpcodes classifies all 256 opcode bytes, as the reference's jump table.
var lzvnOpcodes = func() (t [256]uint8) {
	for op := range 256 {
		switch {
		case op == 6:
			t[op] = opEndOfStream
		case op == 14 || op == 22:
			t[op] = opNop
		case op >= 0xa0 && op <= 0xbf:
			t[op] = opMediumD
		case op == 0xe0:
			t[op] = opLargeL
		case op > 0xe0 && op <= 0xef:
			t[op] = opSmallL
		case op == 0xf0:
			t[op] = opLargeM
		case op > 0xf0:
			t[op] = opSmallM
		case op >= 0x70 && op <= 0x7f, op >= 0xd0 && op <= 0xdf:
			t[op] = opUndefined
		case op&7 == 7:
			t[op] = opLargeD
		case op&7 == 6:
			// 30, 38, ..., 62 are undefined; 70 and up are previous-distance.
			if op < 64 {
				t[op] = opUndefined
			} else {
				t[op] = opPrevD
			}
		default:
			t[op] = opSmallD
		}
	}
	return t
}()

// lzvnDecoder decodes one LZVN stream from src into dst[out:], where matches
// may reach back to dst[0]. It stops at the end-of-stream opcode, at the end
// of either buffer, or at the first invalid opcode or distance; the caller
// tells these apart by where in and out stopped and by endOfStream.
type lzvnDecoder struct {
	src         []byte
	in          int // next source byte
	dst         []byte
	out         int // next destination byte
	endOfStream bool
}

func (v *lzvnDecoder) decode() {
	D := 0 // previous distance
	for v.in < len(v.src) {
		opc := v.src[v.in]
		srcLen := len(v.src) - v.in
		var L, M, opcLen int
		switch lzvnOpcodes[opc] {
		case opSmallD:
			opcLen, L, M = 2, int(opc>>6), int(opc>>3&7)+3
			if srcLen <= opcLen+L {
				return
			}
			D = int(opc&7)<<8 | int(v.src[v.in+1])
		case opMediumD:
			opcLen, L = 3, int(opc>>3&3)
			if srcLen <= opcLen+L {
				return
			}
			opc23 := int(binary.LittleEndian.Uint16(v.src[v.in+1:]))
			M = (int(opc&7)<<2 | opc23&3) + 3
			D = opc23 >> 2
		case opLargeD:
			opcLen, L, M = 3, int(opc>>6), int(opc>>3&7)+3
			if srcLen <= opcLen+L {
				return
			}
			D = int(binary.LittleEndian.Uint16(v.src[v.in+1:]))
		case opPrevD:
			opcLen, L, M = 1, int(opc>>6), int(opc>>3&7)+3
			if srcLen <= opcLen+L {
				return
			}
		case opSmallM:
			opcLen, M = 1, int(opc&0xf)
			if srcLen <= opcLen {
				return
			}
		case opLargeM:
			opcLen = 2
			if srcLen <= opcLen {
				return
			}
			M = int(v.src[v.in+1]) + 16
		case opSmallL:
			opcLen, L = 1, int(opc&0xf)
			if srcLen <= opcLen+L {
				return
			}
		case opLargeL:
			opcLen = 2
			if srcLen <= 2 {
				return
			}
			L = int(v.src[v.in+1]) + 16
			if srcLen <= opcLen+L {
				return
			}
		case opNop:
			if srcLen <= 1 {
				return
			}
			v.in++
			continue
		case opEndOfStream:
			if srcLen < 8 {
				return
			}
			v.in += 8
			v.endOfStream = true
			return
		default:
			return // undefined opcode
		}

		// The literal, then the match. Stopping mid-instruction leaves in
		// and out at its start, as the reference's state does.
		if L > len(v.dst)-v.out {
			return
		}
		lit := v.in + opcLen
		copy(v.dst[v.out:], v.src[lit:lit+L])
		if M == 0 {
			v.in = lit + L
			v.out += L
			continue
		}
		pos := v.out + L
		// A match may not reach before the start of the output, nor have a
		// zero distance. The reference checks this only for the opcodes that
		// carry a literal; the match-only ones reuse a distance already
		// checked, except at the very start of a stream, where they would
		// read unwritten output.
		if D > pos || D == 0 {
			return
		}
		if M > len(v.dst)-pos {
			return
		}
		for i := range M {
			v.dst[pos+i] = v.dst[pos+i-D]
		}
		v.in = lit + L
		v.out = pos + M
	}
}
