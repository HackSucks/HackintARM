package disk

import (
	"bytes"
	"strings"
	"testing"
)

// ADC had no test at all, and reading a real UDCO image panicked with an
// out-of-range index. Two things were wrong: the output buffer was a guess at
// ten times the input, so any chunk that compressed better overran it; and the
// short back-reference computed its distance as "a<<8 | b + 1", which Go parses
// as "a<<8 | (b+1)", so a low byte of 0xff carried into the high bits and
// pointed 256 bytes too far back.

// adcLiterals encodes a run of literal bytes.
func adcLiterals(b []byte) []byte {
	return append([]byte{byte(0x80 | (len(b) - 1))}, b...)
}

func TestDecompressADCLiterals(t *testing.T) {
	want := []byte("the quick brown fox")
	got, err := DecompressADC(adcLiterals(want), len(want))
	if err != nil {
		t.Fatalf("DecompressADC: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestDecompressADCShortReference covers the back-reference that reads into the
// bytes it is producing, which is how a repeated run is encoded: a distance of
// one repeated n times must give n copies of the previous byte, not one byte
// and then garbage.
func TestDecompressADCShortReference(t *testing.T) {
	// One literal 'a', then a short reference back one byte, three times.
	// The control byte's bits 2..5 are the length less three, so 0x00 is the
	// shortest reference there is; its low two bits are the distance's high
	// bits, and the byte after it the low ones, with the whole thing plus one.
	const wantLen = 4
	src := append(adcLiterals([]byte("a")), 0x00, 0x00) // length 3, distance 1
	got, err := DecompressADC(src, wantLen)
	if err != nil {
		t.Fatalf("DecompressADC: %v", err)
	}
	if want := []byte("aaaa"); !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestDecompressADCDistancePrecedence is the precedence bug, pinned. With 256
// bytes produced and a low distance byte of 0xff, the correct distance is 256;
// the buggy expression gives 512, which either reads the wrong bytes or fails
// outright.
func TestDecompressADCDistancePrecedence(t *testing.T) {
	// 256 distinct-ish literal bytes, in runs of 128 (the maximum).
	var src []byte
	first := make([]byte, 128)
	second := make([]byte, 128)
	for i := range first {
		first[i] = byte(i)
		second[i] = byte(128 + i)
	}
	src = append(src, adcLiterals(first)...)
	src = append(src, adcLiterals(second)...)

	// A short reference with distance byte 0xff and the two high bits zero:
	// distance = (0<<8 | 0xff) + 1 = 256, length 3.
	src = append(src, 0x00, 0xff)

	got, err := DecompressADC(src, 256+3)
	if err != nil {
		t.Fatalf("DecompressADC: %v", err)
	}
	// 256 bytes back from offset 256 is the very first byte.
	if want := []byte{0x00, 0x01, 0x02}; !bytes.Equal(got[256:], want) {
		t.Errorf("reference resolved to %v, want %v: the distance was computed wrongly", got[256:], want)
	}
}

// TestDecompressADCRefusesMalformedInput checks the decoder reports a problem
// rather than panicking, which is what it used to do on a perfectly valid image.
func TestDecompressADCRefusesMalformedInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  []byte
		want int
	}{
		{"literal run past the end of the input", []byte{0x8f, 'a', 'b'}, 16},
		{"literal run past the end of the output", adcLiterals([]byte("abcdef")), 2},
		{"reference before the start of the output", []byte{0x04, 0x00}, 8},
		{"truncated short reference", []byte{0x04}, 8},
		{"truncated long reference", []byte{0x40, 0x00}, 8},
		{"stream ends early", adcLiterals([]byte("ab")), 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecompressADC(tc.src, tc.want)
			if err == nil {
				t.Fatalf("accepted malformed input, returning %d bytes", len(got))
			}
			if !strings.HasPrefix(err.Error(), "adc: ") {
				t.Errorf("error %q is not attributed to the ADC decoder", err)
			}
		})
	}
}
