// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package lzfse

import (
	"bytes"
	"os"
	"testing"
)

// fuzzSeeds returns small encoded streams of every block kind.
func fuzzSeeds(f *testing.F) [][]byte {
	var seeds [][]byte
	for _, s := range samples() {
		if len(s.data) > 64<<10 {
			continue // keep the fuzzer's inputs small
		}
		enc, err := Compress(s.data)
		if err != nil {
			f.Fatal(err)
		}
		seeds = append(seeds, enc)
	}
	if b, err := os.ReadFile("testdata/distance-before-start.lzfse"); err == nil {
		seeds = append(seeds, b)
	}
	return seeds
}

// FuzzDecompress feeds arbitrary streams to the decoder, which must return
// an error or data, and never panic or run away with memory.
func FuzzDecompress(f *testing.F) {
	for _, s := range fuzzSeeds(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if n, err := DecodedSize(data); err != nil || n > 16<<20 {
			return
		}
		_, _ = Decompress(data)
	})
}

// FuzzDecompressLZVN feeds arbitrary bare LZVN streams to the LZVN decoder.
func FuzzDecompressLZVN(f *testing.F) {
	for _, s := range samples() {
		if len(s.data) <= 64<<10 {
			f.Add(CompressLZVN(s.data), len(s.data))
		}
	}
	f.Fuzz(func(t *testing.T, data []byte, size int) {
		if size < 0 || size > 1<<20 {
			return
		}
		_, _ = DecompressLZVN(data, size)
	})
}

// FuzzRoundTrip requires every input to survive both encoders unchanged.
func FuzzRoundTrip(f *testing.F) {
	for _, s := range samples() {
		if len(s.data) <= 64<<10 {
			f.Add(s.data)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		enc, err := Compress(data)
		if err != nil {
			t.Fatal(err)
		}
		dec, err := Decompress(enc)
		if err != nil {
			t.Fatalf("Decompress of our own stream: %v", err)
		}
		if !bytes.Equal(dec, data) {
			t.Fatal("LZFSE round trip changed the data")
		}
		for _, capacity := range []int{len(data), len(enc) + 64} {
			dst := make([]byte, capacity)
			if n := EncodeBuffer(dst, data); n != 0 {
				got, err := Decompress(dst[:n])
				if err != nil || !bytes.Equal(got, data) {
					t.Fatalf("bounded LZFSE: %v", err)
				}
			}
			if n := EncodeLZVNBuffer(dst, data); n != 0 {
				got, err := DecompressLZVN(dst[:n], len(data))
				if err != nil || !bytes.Equal(got, data) {
					t.Fatalf("bounded LZVN: %v", err)
				}
			}
		}
		lz := CompressLZVN(data)
		dec, err = DecompressLZVN(lz, len(data))
		if err != nil {
			t.Fatalf("DecompressLZVN of our own stream: %v", err)
		}
		if !bytes.Equal(dec, data) {
			t.Fatal("LZVN round trip changed the data")
		}
	})
}
