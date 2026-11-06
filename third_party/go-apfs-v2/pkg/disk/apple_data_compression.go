// Apple Data Compression (ADC) decompressor.
//
// ADC is the codec behind UDCO images. It is a byte-oriented LZ77: each control
// byte introduces either a run of literal bytes or a back-reference into what
// has already been produced.
package disk

import "fmt"

// DecompressADC decompresses an ADC stream into exactly want bytes.
//
// The caller always knows how long the answer is — a DMG chunk declares it —
// and passing it in is what makes the decoder safe. Deriving the size from the
// input instead means guessing a compression ratio, and a guess that is too
// small turns a valid stream into an out-of-range panic.
func DecompressADC(src []byte, want int) ([]byte, error) {
	if want < 0 {
		return nil, fmt.Errorf("adc: negative output size %d", want)
	}
	dst := make([]byte, want)

	i, o := 0, 0
	for i < len(src) && o < want {
		ctl := int(src[i])
		i++

		switch {
		case ctl&0x80 != 0:
			// A run of literals: the low seven bits are the count, less one.
			n := ctl&0x7f + 1
			if i+n > len(src) {
				return nil, fmt.Errorf("adc: literal run of %d bytes runs past the end of %d bytes of input", n, len(src))
			}
			if o+n > want {
				return nil, fmt.Errorf("adc: literal run of %d bytes overruns the %d-byte output", n, want)
			}
			copy(dst[o:], src[i:i+n])
			i += n
			o += n

		case ctl&0x40 != 0:
			// A long back-reference: a two-byte distance follows.
			if i+2 > len(src) {
				return nil, fmt.Errorf("adc: truncated long reference at offset %d", i)
			}
			n := ctl - 0x3c
			dist := (int(src[i])<<8 | int(src[i+1])) + 1
			i += 2
			if err := copyRef(dst, &o, want, dist, n); err != nil {
				return nil, err
			}

		default:
			// A short back-reference: the distance's low byte follows. The
			// parenthesising matters -- "a<<8 | b + 1" is "a<<8 | (b+1)" in Go,
			// so a low byte of 0xff would carry into the high bits and give a
			// distance 256 too far back.
			if i >= len(src) {
				return nil, fmt.Errorf("adc: truncated short reference at offset %d", i)
			}
			n := (ctl>>2)&0x0f + 3
			dist := ((ctl&0x03)<<8 | int(src[i])) + 1
			i++
			if err := copyRef(dst, &o, want, dist, n); err != nil {
				return nil, err
			}
		}
	}

	if o != want {
		return nil, fmt.Errorf("adc: stream produced %d bytes, want %d", o, want)
	}
	return dst, nil
}

// copyRef copies n bytes from dist bytes back in the output.
//
// The copy is byte by byte on purpose: a reference may reach into the bytes it
// is itself producing, which is how a repeated run is encoded, so a bulk copy
// would give the wrong answer whenever dist is less than n.
func copyRef(dst []byte, o *int, want, dist, n int) error {
	if dist <= 0 || dist > *o {
		return fmt.Errorf("adc: reference %d bytes back with only %d bytes produced", dist, *o)
	}
	if *o+n > want {
		return fmt.Errorf("adc: reference of %d bytes overruns the %d-byte output", n, want)
	}
	for range n {
		dst[*o] = dst[*o-dist]
		*o++
	}
	return nil
}
