// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package lzfse

import (
	"bytes"
	"fmt"
	"math/rand"
)

// sampleInput is one deterministic test input. Its bytes come from the name
// alone, so the golden hashes below can be regenerated with Apple's encoder.
type sampleInput struct {
	name string
	data []byte
}

// samples returns inputs covering each encoder path: uncompressed (under eight
// bytes, or incompressible), LZVN (under 4 KiB), and LZFSE blocks, one and
// several, with long matches, long literal runs and runs of zeros.
func samples() []sampleInput {
	rng := func(seed int64, n int) []byte {
		b := make([]byte, n)
		rand.New(rand.NewSource(seed)).Read(b)
		return b
	}
	text := func(n int) []byte {
		var buf bytes.Buffer
		for i := 0; buf.Len() < n; i++ {
			fmt.Fprintf(&buf, "line %d of the quick brown fox %d\n", i, i*7919%1000)
		}
		return buf.Bytes()[:n]
	}
	// A long incompressible run and then a repeat of its start: the literal
	// run is split, and the split records must not carry the repeat's
	// distance (see pushMatch).
	longLiteralThenRepeat := func() []byte {
		r := rng(1, 1000)
		b := append(append([]byte{}, r...), r[:100]...)
		return append(b, bytes.Repeat([]byte("compressible text "), 4000)...)
	}
	// Records every 4 KiB, like a disk image's metadata: a header that varies
	// and a body that repeats across records.
	records := func(n int) []byte {
		b := make([]byte, 0, n)
		for i := 0; len(b) < n; i++ {
			rec := make([]byte, 4096)
			copy(rec, fmt.Sprintf("record %08d", i))
			copy(rec[64:], rng(int64(i%7), 200))
			b = append(b, rec...)
		}
		return b[:n]
	}
	return []sampleInput{
		{"empty", nil},
		{"five-random", rng(2, 5)},
		{"seven-random", rng(3, 7)},
		{"eight-random", rng(4, 8)},
		{"text-100", text(100)},
		{"text-3000", text(3000)},
		{"text-4095", text(4095)},
		{"text-4096", text(4096)},
		{"random-5000", rng(5, 5000)},
		{"random-300k", rng(6, 300_000)},
		{"zeros-2m", make([]byte, 2_000_000)},
		{"text-1500k", text(1_500_000)},
		{"records-3000", records(3000)},
		{"records-4000", records(4000)[1000:]},
		{"text-mixed-3500", append(text(2000), rng(7, 1500)...)},
		{"long-literal-then-repeat", longLiteralThenRepeat()},
		{"records-1m", records(1 << 20)},
	}
}
