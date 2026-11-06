// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2015-2016, Apple Inc. All rights reserved.
// Copyright (c) 2026 Deployment Theory.
//
// Format constants and value tables, after Apple's reference implementation
// (lzfse_internal.h, lzfse_tunables.h, lzfse_encode_tables.h). See LICENSE in
// this directory.

package lzfse

// Block magics, little-endian "bvx?".
const (
	magicEndOfStream = 0x24787662 // bvx$
	magicRaw         = 0x2d787662 // bvx- uncompressed
	magicV1          = 0x31787662 // bvx1 LZFSE, uncompressed tables
	magicV2          = 0x32787662 // bvx2 LZFSE, compressed tables
	magicLZVN        = 0x6e787662 // bvxn LZVN
)

// Encoder tunables.
const (
	encodeHashBits      = 14
	encodeHashWidth     = 4
	encodeGoodMatch     = 40
	encodeLZVNThreshold = 4096
	encodeHashValues    = 1 << encodeHashBits
)

// Symbol and state counts of the four FSE streams.
const (
	lSymbols       = 20
	mSymbols       = 20
	dSymbols       = 64
	literalSymbols = 256

	lStates       = 64
	mStates       = 64
	dStates       = 256
	literalStates = 1024
)

// Per-block limits.
const (
	matchesPerBlock  = 10000
	literalsPerBlock = 4 * matchesPerBlock
)

// Largest L, M and D one LMD record can carry.
const (
	maxLValue = 315
	maxMValue = 2359
	maxDValue = 262139
)

// maxMatchLength bounds a match found forward, so that it does not split into
// too many LMD records.
const maxMatchLength = 100 * maxMValue

// Sizes of the fixed parts of the block headers.
const (
	rawHeaderSize  = 8  // magic, n_raw_bytes
	lzvnHeaderSize = 12 // magic, n_raw_bytes, n_payload_bytes
	v2FixedSize    = 32 // magic, n_raw_bytes, packed_fields[3]
	// lzfse_compressed_block_header_v1: 50 bytes of fields and 720 of
	// tables, padded to the struct's 4-byte alignment.
	v1HeaderSize = 772
)

// Each L, M and D value is coded as an FSE symbol naming a base value, plus
// that symbol's number of extra bits holding the difference.
var (
	lExtraBits = [lSymbols]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8}
	lBaseValue = [lSymbols]int32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60}
	mExtraBits = [mSymbols]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11}
	mBaseValue = [mSymbols]int32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312}
	dExtraBits = [dSymbols]uint8{
		0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
		4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
		8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11,
		12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15,
	}
	dBaseValue = [dSymbols]int32{
		0, 1, 2, 3, 4, 6, 8, 10, 12, 16,
		20, 24, 28, 36, 44, 52, 60, 76, 92, 108,
		124, 156, 188, 220, 252, 316, 380, 444, 508, 636,
		764, 892, 1020, 1276, 1532, 1788, 2044, 2556, 3068, 3580,
		4092, 5116, 6140, 7164, 8188, 10236, 12284, 14332, 16380, 20476,
		24572, 28668, 32764, 40956, 49148, 57340, 65532, 81916, 98300, 114684,
		131068, 163836, 196604, 229372,
	}
)

// The inverse maps, value to symbol. The reference spells them out as tables;
// they are the symbol whose base is the largest not above the value, which is
// what these build.
var (
	lSymbolOf = inverseBase(lBaseValue[:], maxLValue)
	mSymbolOf = inverseBase(mBaseValue[:], maxMValue)
	dSymbolOf = inverseBase(dBaseValue[:], maxDValue)
)

func inverseBase(base []int32, maxValue int) []uint8 {
	sym := make([]uint8, maxValue+1)
	s := 0
	for v := range sym {
		for s+1 < len(base) && int(base[s+1]) <= v {
			s++
		}
		sym[v] = uint8(s)
	}
	return sym
}
