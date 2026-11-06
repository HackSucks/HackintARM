// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package lzfse

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"testing"
)

// A zero-sized V2 header used to leave DecodedSize spinning at the same block.
// Every undersized header is corrupt, even when its payload would advance it.
func TestRejectsUndersizedV2Header(t *testing.T) {
	for header := uint32(0); header < v2FixedSize; header++ {
		for _, payload := range []uint64{0, 1} {
			t.Run(fmt.Sprintf("header=%d/payload=%d", header, payload), func(t *testing.T) {
				src := make([]byte, v2FixedSize+int(payload))
				copy(src, "bvx2")
				binary.LittleEndian.PutUint32(src[24:], header)
				binary.LittleEndian.PutUint64(src[8:], payload<<20)
				if _, err := DecodedSize(src); !errors.Is(err, ErrCorrupt) {
					t.Fatalf("DecodedSize: %v, want ErrCorrupt", err)
				}
				if _, err := Decompress(src); !errors.Is(err, ErrCorrupt) {
					t.Fatalf("Decompress: %v, want ErrCorrupt", err)
				}
				// Exercise the decoder's guard without going through DecodedSize.
				if _, err := DecompressInto(make([]byte, 64<<10), src); !errors.Is(err, ErrCorrupt) {
					t.Fatalf("DecompressInto: %v, want ErrCorrupt", err)
				}
			})
		}
	}
}

// Even with empty payloads, each block must advance to the following block.
// DecodedSize only scans headers; these need not contain valid codec tables.
func TestDecodedSizeEmptyPayloadAdvances(t *testing.T) {
	for _, tc := range []struct {
		magic  string
		header int
	}{
		{"bvx-", rawHeaderSize},
		{"bvxn", lzvnHeaderSize},
		{"bvx1", v1HeaderSize},
		{"bvx2", v2FixedSize},
	} {
		t.Run(tc.magic, func(t *testing.T) {
			src := make([]byte, tc.header)
			copy(src, tc.magic)
			if tc.magic == "bvx2" {
				binary.LittleEndian.PutUint32(src[24:], uint32(tc.header))
			}
			if _, err := DecodedSize(src); !errors.Is(err, ErrTruncated) {
				t.Fatalf("missing end marker: %v, want ErrTruncated", err)
			}
			src = append(src, []byte("bvx$")...)
			if n, err := DecodedSize(src); err != nil || n != 0 {
				t.Fatalf("DecodedSize = %d, %v, want 0, nil", n, err)
			}
		})
	}
}

// TestRejectsDistanceBeforeStart decodes a stream that
// github.com/go-compressions/lzfse wrote: a long literal run split into
// records that carried the following match's distance, which reaches before
// the start of the output. Apple's decoder refuses it (compression_tool
// -decode fails) and so must this one; its predecessor decoded it silently,
// which is how hdiutil came to reject DMGs this module had verified.
func TestRejectsDistanceBeforeStart(t *testing.T) {
	src, err := os.ReadFile("testdata/distance-before-start.lzfse")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decompress(src); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v, want ErrCorrupt", err)
	}
}

// TestSplitLiteralsCarryDistanceOne encodes the input that produced that
// stream and checks the split records now decode under the strict check.
func TestSplitLiteralsCarryDistanceOne(t *testing.T) {
	for _, s := range samples() {
		if s.name != "long-literal-then-repeat" {
			continue
		}
		enc, err := Compress(s.data)
		if err != nil {
			t.Fatal(err)
		}
		dec, err := Decompress(enc)
		if err != nil {
			t.Fatalf("Decompress: %v", err)
		}
		if !bytes.Equal(dec, s.data) {
			t.Fatal("round trip changed the data")
		}
		return
	}
	t.Fatal("sample not found")
}

// TestDistanceSymbolTable checks the derived value-to-symbol map for D against
// the reference's d_base_from_value, a 256-entry table indexed by range.
func TestDistanceSymbolTable(t *testing.T) {
	sym := [256]uint8{
		0, 1, 2, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 8, 8, 9, 9,
		9, 9, 10, 10, 10, 10, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12,
		13, 13, 13, 13, 13, 13, 13, 13, 14, 14, 14, 14, 14, 14, 14, 14, 15, 15,
		15, 15, 15, 15, 15, 15, 16, 16, 16, 16, 16, 17, 18, 19, 20, 20, 21, 21,
		22, 22, 23, 23, 24, 24, 24, 24, 25, 25, 25, 25, 26, 26, 26, 26, 27, 27,
		27, 27, 28, 28, 28, 28, 28, 28, 28, 28, 29, 29, 29, 29, 29, 29, 29, 29,
		30, 30, 30, 30, 30, 30, 30, 30, 31, 31, 31, 31, 31, 31, 31, 31, 32, 32,
		32, 32, 32, 33, 34, 35, 36, 36, 37, 37, 38, 38, 39, 39, 40, 40, 40, 40,
		41, 41, 41, 41, 42, 42, 42, 42, 43, 43, 43, 43, 44, 44, 44, 44, 44, 44,
		44, 44, 45, 45, 45, 45, 45, 45, 45, 45, 46, 46, 46, 46, 46, 46, 46, 46,
		47, 47, 47, 47, 47, 47, 47, 47, 48, 48, 48, 48, 48, 49, 50, 51, 52, 52,
		53, 53, 54, 54, 55, 55, 56, 56, 56, 56, 57, 57, 57, 57, 58, 58, 58, 58,
		59, 59, 59, 59, 60, 60, 60, 60, 60, 60, 60, 60, 61, 61, 61, 61, 61, 61,
		61, 61, 62, 62, 62, 62, 62, 62, 62, 62, 63, 63, 63, 63, 63, 63, 63, 63,
		0, 0, 0, 0,
	}
	reference := func(v int) uint8 {
		switch {
		case v < 60:
			return sym[v]
		case v < 1020:
			return sym[(v-60)>>4+64]
		case v < 16380:
			return sym[(v-1020)>>8+128]
		default:
			return sym[(v-16380)>>12+192]
		}
	}
	for v := 0; v <= maxDValue; v++ {
		if got, want := dSymbolOf[v], reference(v); got != want {
			t.Fatalf("D %d: symbol %d, reference %d", v, got, want)
		}
	}
}

// TestLZVNOpcodeTable checks the opcode classes against the reference's jump
// table, row by row.
func TestLZVNOpcodeTable(t *testing.T) {
	const (
		s = opSmallD
		m = opMediumD
		l = opLargeD
		p = opPrevD
		n = opNop
		e = opEndOfStream
		u = opUndefined
	)
	rows := [][8]uint8{
		{s, s, s, s, s, s, e, l}, {s, s, s, s, s, s, n, l}, {s, s, s, s, s, s, n, l}, {s, s, s, s, s, s, u, l},
		{s, s, s, s, s, s, u, l}, {s, s, s, s, s, s, u, l}, {s, s, s, s, s, s, u, l}, {s, s, s, s, s, s, u, l},
		{s, s, s, s, s, s, p, l}, {s, s, s, s, s, s, p, l}, {s, s, s, s, s, s, p, l}, {s, s, s, s, s, s, p, l},
		{s, s, s, s, s, s, p, l}, {s, s, s, s, s, s, p, l}, {u, u, u, u, u, u, u, u}, {u, u, u, u, u, u, u, u},
		{s, s, s, s, s, s, p, l}, {s, s, s, s, s, s, p, l}, {s, s, s, s, s, s, p, l}, {s, s, s, s, s, s, p, l},
		{m, m, m, m, m, m, m, m}, {m, m, m, m, m, m, m, m}, {m, m, m, m, m, m, m, m}, {m, m, m, m, m, m, m, m},
		{s, s, s, s, s, s, p, l}, {s, s, s, s, s, s, p, l}, {u, u, u, u, u, u, u, u}, {u, u, u, u, u, u, u, u},
		{opLargeL, opSmallL, opSmallL, opSmallL, opSmallL, opSmallL, opSmallL, opSmallL},
		{opSmallL, opSmallL, opSmallL, opSmallL, opSmallL, opSmallL, opSmallL, opSmallL},
		{opLargeM, opSmallM, opSmallM, opSmallM, opSmallM, opSmallM, opSmallM, opSmallM},
		{opSmallM, opSmallM, opSmallM, opSmallM, opSmallM, opSmallM, opSmallM, opSmallM},
	}
	for r, row := range rows {
		for c, want := range row {
			if op := r*8 + c; lzvnOpcodes[op] != want {
				t.Errorf("opcode %d: class %d, reference %d", op, lzvnOpcodes[op], want)
			}
		}
	}
}

// testInputs returns inputs of many sizes and kinds for round trips.
func testInputs() [][]byte {
	rng := rand.New(rand.NewSource(42))
	var out [][]byte
	for _, n := range []int{0, 1, 7, 8, 9, 15, 16, 100, 271, 272, 1000, 4095, 4096, 4097, 10_000, 65_536, 300_000} {
		random := make([]byte, n)
		rng.Read(random)
		repeated := bytes.Repeat([]byte("abcdefgh"), n/8+1)[:n]
		// Mostly repetitive, with random bytes sprinkled in.
		mixed := bytes.Repeat([]byte("the quick brown fox "), n/20+1)[:n]
		for i := 0; i < n; i += 37 {
			mixed[i] = byte(rng.Intn(256))
		}
		out = append(out, random, repeated, mixed, make([]byte, n))
	}
	return out
}

func TestRoundTrip(t *testing.T) {
	for _, in := range testInputs() {
		enc, err := Compress(in)
		if err != nil {
			t.Fatalf("%d bytes: Compress: %v", len(in), err)
		}
		if len(enc) > len(in)+12 {
			t.Fatalf("%d bytes grew to %d", len(in), len(enc))
		}
		dec, err := Decompress(enc)
		if err != nil {
			t.Fatalf("%d bytes: Decompress: %v", len(in), err)
		}
		if !bytes.Equal(dec, in) {
			t.Fatalf("%d bytes: round trip changed the data", len(in))
		}
		if n, err := DecodedSize(enc); err != nil || n != len(in) {
			t.Fatalf("%d bytes: DecodedSize = %d, %v", len(in), n, err)
		}
	}
}

func TestRoundTripLZVN(t *testing.T) {
	for _, in := range testInputs() {
		enc := CompressLZVN(in)
		if len(enc) == 0 {
			t.Fatalf("%d bytes: CompressLZVN failed", len(in))
		}
		dec, err := DecompressLZVN(enc, len(in))
		if err != nil {
			t.Fatalf("%d bytes: DecompressLZVN: %v", len(in), err)
		}
		if !bytes.Equal(dec, in) {
			t.Fatalf("%d bytes: round trip changed the data", len(in))
		}
	}
}

// TestDecompressIntoLimit checks an output buffer that is too small is an
// error, not a truncated success.
func TestDecompressIntoLimit(t *testing.T) {
	in := bytes.Repeat([]byte("0123456789"), 10_000)
	enc, err := Compress(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecompressInto(make([]byte, len(in)-1), enc); !errors.Is(err, ErrOutputFull) {
		t.Fatalf("err = %v, want ErrOutputFull", err)
	}
	n, err := DecompressInto(make([]byte, len(in)), enc)
	if err != nil || n != len(in) {
		t.Fatalf("exact buffer: %d, %v", n, err)
	}
}

// TestTruncatedAndCorruptStreams cuts and damages valid streams of each block
// kind. Every result must be an error or correct output, never a panic.
func TestTruncatedAndCorruptStreams(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for _, s := range samples() {
		enc, err := Compress(s.data)
		if err != nil {
			t.Fatal(err)
		}
		for cut := 0; cut < len(enc); cut += max(1, len(enc)/200) {
			if _, err := Decompress(enc[:cut]); err == nil {
				t.Fatalf("%s: stream cut at %d of %d decoded", s.name, cut, len(enc))
			}
		}
		for range 200 {
			bad := bytes.Clone(enc)
			bad[rng.Intn(len(bad))] ^= byte(1 + rng.Intn(255))
			_, _ = DecompressInto(make([]byte, len(s.data)), bad)
			_, _ = DecompressLZVN(bad, len(s.data))
		}
	}
}
