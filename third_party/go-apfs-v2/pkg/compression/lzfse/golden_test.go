// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package lzfse

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// appleEncodeSHA256 is the SHA-256 of what Apple's libcompression writes for
// each sample: compression_encode_buffer(dst, cap, src, n, NULL,
// COMPRESSION_LZFSE) with cap = n + 4096 + n/4, on macOS 27. That is the call
// that encodes a DMG chunk. The open-source reference encoder writes the same
// bytes for every sample.
//
// To regenerate: write each sample to a file and run it through a small C
// program linked with -lcompression that makes that call.
var appleEncodeSHA256 = map[string]string{
	"empty":                    "9502b7226136d6e97cbe78c04ac9ea572595fc7b25ae1394759d45a1796b86ff",
	"five-random":              "de18504f266a53c47c12542be85b8f20befc95f7d0dc66bf9a4ca3cbba24b484",
	"seven-random":             "a06c9d47596b4bf4ffb827341e21025a0e66135a5f57b6963029bbe2e4c393ff",
	"eight-random":             "2a97f481a11a5c8a96d85ce8240598c1377bb29e5990564bb00953410c63f70a",
	"text-100":                 "ea0ff823c62d02d270f826aa842a7f77929a1c18b79a31acb39e5eb52931ef91",
	"text-3000":                "f68e54d475ffa7404cb057eb2a6806c13441543524973906207c189b8a23a07b",
	"text-4095":                "fc441c8ab9bffc293b17f28a1887b8373897e094ea6ba4188618439d41d51b15",
	"text-4096":                "2a0bc81adab8ba6024bae722bc85307e3948f36b5a1b5ecce66e72095f81a4a6",
	"random-5000":              "211ac609f0c238ba4f58331719625c17c8dbb34bf3d2065dfa7f5c4f302cbd92",
	"random-300k":              "51f93512746c107e21e4e7dad3290a34cd0e66c7ddf71193982fef50d7648839",
	"zeros-2m":                 "f32ac93d294a643b86d5b937db1600c3f03c42cdad56a84705c702a78855fcdc",
	"text-1500k":               "2cb8a7a63934c7c4fb48966e0f95be60cc5ae09e2ad876507bf7f360199cc07b",
	"records-3000":             "29e0debabe45685d8c57f627ed32d56d7ba5e0f7244eb0b6b610960eaeb389ca",
	"records-4000":             "27b4eb87c07c9092ef76ef02dd1da0642a6fdfe5b8ad9bf8a56515ef980dfe76",
	"text-mixed-3500":          "7bb402697db8a00fab722baf6d6e7ea7f22c287817427b2a81871c26b354e417",
	"long-literal-then-repeat": "821a187b9191cdb124676623f7eb1387fa8998935148a5122d2c08afd2d0ce3c",
	"records-1m":               "894200caf8aab09ce268c7387ae44e4ef77d0360e34b4368721c5081b5acc232",
}

// TestEncodeMatchesApple requires the encoder to write exactly what Apple's
// does, and every result to decode back to its input.
func TestEncodeMatchesApple(t *testing.T) {
	for _, s := range samples() {
		t.Run(s.name, func(t *testing.T) {
			want, ok := appleEncodeSHA256[s.name]
			if !ok {
				t.Fatalf("no Apple hash recorded for sample %q", s.name)
			}
			n := len(s.data)
			dst := make([]byte, n+4096+n/4)
			m := EncodeBuffer(dst, s.data)
			if m == 0 {
				t.Fatal("EncodeBuffer failed")
			}
			sum := sha256.Sum256(dst[:m])
			if got := hex.EncodeToString(sum[:]); got != want {
				t.Errorf("encoded %d bytes to %d with SHA-256 %s; Apple's is %s", n, m, got, want)
			}
			back, err := Decompress(dst[:m])
			if err != nil {
				t.Fatalf("Decompress: %v", err)
			}
			if !bytes.Equal(back, s.data) {
				t.Error("round trip changed the data")
			}
		})
	}
}
