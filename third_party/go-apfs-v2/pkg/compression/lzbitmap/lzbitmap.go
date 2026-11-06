// Package lzbitmap decodes and encodes Apple's LZBITMAP compression, the
// codec behind the pbzb payload container.
//
// Apple publishes no specification. The format below is Ernesto A.
// Fernandez's, reverse-engineered by black-box testing for Corellium's
// libzbitmap (MIT); this package is a Go translation of that work, and
// carries its copyright notice in NOTICE. Correctness is judged against
// Apple's own output: testdata/aa holds an archive produced by
// "aa archive -a lzbitmap" and the same archive uncompressed, and the
// tests decode one into the other.
//
// A stream is the magic "ZBM\x09" followed by chunks, ending with a chunk
// whose decompressed length is zero. Every length is a 24-bit
// little-endian integer.
//
//	chunk header    len u24, decmpLen u24            (6 bytes)
//	compressed also metaOff1 u24, metaOff2 u24,
//	                metaOff3 u24                     (9 more)
//
// len counts the header. A chunk whose len is exactly decmpLen + 6 holds
// plain bytes. Otherwise it is compressed, and holds four regions: the
// literal data, which starts after the header, and three metadata areas
// at the offsets in the header, all relative to the start of the chunk.
//
// The last 17 bytes of a compressed chunk are 12 bitmap descriptors of 10
// bits each, read least-significant bit first: 8 bits of bitmap, then 2
// bits saying how many bytes to read from the first metadata area for a
// new repetition period.
//
// Decoding walks the third metadata area a nibble at a time. Each nibble
// selects a bitmap: 3 to 14 index the 12 descriptors, 0 to 2 mean "take
// the next byte of the second metadata area as the bitmap, with this many
// period bytes", and 15 introduces a repetition count. A bitmap emits 8
// bytes, one per bit: a 1 copies the next literal byte, a 0 copies the
// byte one period back in the output, which may reach into a previous
// chunk. A repetition count is nibbles summed after a base of 4, since
// repeating fewer than four times would not save space.
package lzbitmap

import (
	"errors"
	"fmt"
)

// Magic is the four bytes an LZBITMAP stream starts with.
const Magic = "ZBM\x09"

// ErrFormat reports bytes that are not a valid LZBITMAP stream.
var ErrFormat = errors.New("lzbitmap: invalid stream")

const (
	magicSize = 4
	// MaxChunk is the largest a chunk may decompress to.
	MaxChunk = 0x8000

	chunkHdrSize    = 6  // len u24 + decmpLen u24
	cmpChunkHdrSize = 15 // and three u24 metadata offsets

	bitmapCount     = 12 // nibbles 3 to 14
	bitmapBase      = 3
	bitmapByteCount = 17 // the descriptors sit in the last 17 bytes
	maxPeriodBytes  = 2

	repeatBase = 4 // a repetition count starts here
)

// bmap is one bitmap descriptor: the eight bits to apply, and how many
// bytes of new repetition period precede it.
type bmap struct {
	bitmap      byte
	periodBytes byte
}

// u24 reads a 24-bit little-endian integer.
func u24(b []byte) int { return int(b[0]) | int(b[1])<<8 | int(b[2])<<16 }

// putU24 writes a 24-bit little-endian integer.
func putU24(b []byte, v int) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
}

type decoder struct {
	src     []byte
	out     []byte
	limit   int
	bounded bool

	pos int // start of the current chunk
	end int // one past its last byte

	decmpLen   int
	written    int
	prewritten int
	period     int

	data  int // next literal byte
	meta1 int // repetition periods
	meta2 int // inline bitmaps
	meta3 int // bitmap numbers, a nibble at a time
	nib   int // 0 for the low nibble of src[meta3], 1 for the high

	bitmaps [bitmapCount]bmap
}

// Decompress decodes a whole LZBITMAP stream.
func Decompress(src []byte) ([]byte, error) {
	return decode(src, -1)
}

// DecompressLimit decodes while bounding the total allocation by maxOutput.
// The limit is checked before each chunk can grow the output buffer.
func DecompressLimit(src []byte, maxOutput int) ([]byte, error) {
	if maxOutput < 0 {
		return nil, fmt.Errorf("%w: negative output limit", ErrFormat)
	}
	return decode(src, maxOutput)
}

func decode(src []byte, limit int) ([]byte, error) {
	if len(src) < magicSize || string(src[:magicSize]) != Magic {
		return nil, fmt.Errorf("%w: not %q", ErrFormat, Magic)
	}
	d := &decoder{src: src, pos: magicSize, limit: limit, bounded: limit >= 0}
	for {
		if err := d.chunk(); err != nil {
			return nil, err
		}
		d.pos = d.end
		d.prewritten += d.decmpLen
		if d.decmpLen == 0 {
			return d.out, nil
		}
	}
}

// chunk decodes the chunk at d.pos.
func (d *decoder) chunk() error {
	if d.pos+chunkHdrSize > len(d.src) {
		return fmt.Errorf("%w: truncated chunk header", ErrFormat)
	}
	length := u24(d.src[d.pos:])
	if length < chunkHdrSize || d.pos+length > len(d.src) {
		return fmt.Errorf("%w: chunk length %d outside the stream", ErrFormat, length)
	}
	d.end = d.pos + length
	d.decmpLen = u24(d.src[d.pos+3:])
	if d.bounded && d.decmpLen > d.limit-len(d.out) {
		return fmt.Errorf("%w: output exceeds %d-byte limit", ErrFormat, d.limit)
	}
	if d.decmpLen > MaxChunk {
		return fmt.Errorf("%w: chunk decompresses to %d, over the %d limit", ErrFormat, d.decmpLen, MaxChunk)
	}
	if length == d.decmpLen+chunkHdrSize {
		// Plain bytes behind a header.
		d.out = append(d.out, d.src[d.pos+chunkHdrSize:d.end]...)
		d.written = d.decmpLen
		return nil
	}
	return d.compressedChunk(length)
}

func (d *decoder) compressedChunk(length int) error {
	if length < cmpChunkHdrSize {
		return fmt.Errorf("%w: compressed chunk of %d bytes has no header", ErrFormat, length)
	}
	d.written = 0
	d.period = 8
	d.data = d.pos + cmpChunkHdrSize
	off1, off2, off3 := u24(d.src[d.pos+6:]), u24(d.src[d.pos+9:]), u24(d.src[d.pos+12:])
	if off1 >= length || off2 >= length || off3 >= length {
		return fmt.Errorf("%w: metadata offset outside the chunk", ErrFormat)
	}
	d.meta1, d.meta2, d.meta3, d.nib = d.pos+off1, d.pos+off2, d.pos+off3, 0
	if err := d.readBitmaps(length); err != nil {
		return err
	}
	for d.written < d.decmpLen {
		if err := d.oneBitmap(); err != nil {
			return err
		}
	}
	return nil
}

// readBitmaps reads the 12 descriptors from the chunk's last 17 bytes.
func (d *decoder) readBitmaps(length int) error {
	if length < bitmapByteCount {
		return fmt.Errorf("%w: chunk too short to hold its bitmaps", ErrFormat)
	}
	at, bit := d.end-bitmapByteCount, 0
	next := func() (int, error) {
		if at >= d.end {
			return 0, fmt.Errorf("%w: bitmaps run past the chunk", ErrFormat)
		}
		v := int(d.src[at]>>bit) & 1
		bit++
		if bit == 8 {
			bit = 0
			at++
		}
		return v, nil
	}
	for i := range d.bitmaps {
		var b bmap
		for j := 0; j < 8; j++ {
			v, err := next()
			if err != nil {
				return err
			}
			b.bitmap |= byte(v << j)
		}
		for j := 0; j < 2; j++ {
			v, err := next()
			if err != nil {
				return err
			}
			b.periodBytes |= byte(v << j)
		}
		if b.periodBytes > maxPeriodBytes {
			return fmt.Errorf("%w: bitmap %d wants %d period bytes", ErrFormat, i, b.periodBytes)
		}
		d.bitmaps[i] = b
	}
	return nil
}

func (d *decoder) readNibble() (byte, error) {
	if d.meta3 >= d.end {
		return 0, fmt.Errorf("%w: bitmap numbers run past the chunk", ErrFormat)
	}
	var v byte
	if d.nib == 0 {
		v = d.src[d.meta3] & 0xf
		d.nib = 1
	} else {
		v = d.src[d.meta3] >> 4
		d.nib = 0
		d.meta3++
	}
	return v, nil
}

func (d *decoder) rewindNibble() {
	if d.nib == 0 {
		d.nib = 1
		d.meta3--
	} else {
		d.nib = 0
	}
}

// oneBitmap applies the bitmap the next nibble names, as many times as
// the repetition count that follows it says.
func (d *decoder) oneBitmap() error {
	num, err := d.readNibble()
	if err != nil {
		return err
	}
	repeat, err := d.repetitionCount()
	if err != nil {
		return err
	}
	for i := 0; i < repeat; i++ {
		if err := d.applyNumber(num); err != nil {
			return err
		}
	}
	return nil
}

// repetitionCount reads the count that may follow a bitmap number. The
// trailing bitmaps of a chunk never carry one, or it could not be told
// apart from a bitmap number.
func (d *decoder) repetitionCount() (int, error) {
	if d.decmpLen-d.written <= 8 {
		return 1, nil
	}
	nib, err := d.readNibble()
	if err != nil {
		return 0, err
	}
	if nib != 0xf {
		d.rewindNibble()
		return 1, nil
	}
	total := repeatBase
	for nib == 0xf {
		if nib, err = d.readNibble(); err != nil {
			return 0, err
		}
		total += int(nib)
		if total > MaxChunk {
			return 0, fmt.Errorf("%w: repetition count over %d", ErrFormat, MaxChunk)
		}
	}
	return total, nil
}

// applyNumber turns a nibble into a bitmap and applies it. Numbers at or
// below maxPeriodBytes take the bitmap inline from the second metadata
// area; the rest index the descriptors read from the chunk's tail.
func (d *decoder) applyNumber(num byte) error {
	if num == 0xf {
		return fmt.Errorf("%w: 0xf is a repetition marker, not a bitmap", ErrFormat)
	}
	if int(num) > maxPeriodBytes {
		return d.apply(d.bitmaps[int(num)-bitmapBase])
	}
	if d.meta2 >= d.end {
		return fmt.Errorf("%w: inline bitmaps run past the chunk", ErrFormat)
	}
	b := bmap{bitmap: d.src[d.meta2], periodBytes: num}
	d.meta2++
	return d.apply(b)
}

// apply emits up to eight bytes, one per bit: a set bit copies a literal,
// a clear bit copies the byte one period back in the output.
func (d *decoder) apply(b bmap) error {
	if b.periodBytes > 0 {
		d.period = 0
		for i := 0; i < int(b.periodBytes); i++ {
			if d.meta1 >= d.end {
				return fmt.Errorf("%w: periods run past the chunk", ErrFormat)
			}
			d.period |= int(d.src[d.meta1]) << (i * 8)
			d.meta1++
		}
	}
	if d.period == 0 {
		return fmt.Errorf("%w: zero repetition period", ErrFormat)
	}
	for i := 0; i < 8; i++ {
		if d.written == d.decmpLen {
			break
		}
		if b.bitmap&(1<<i) != 0 {
			if d.data >= d.end {
				return fmt.Errorf("%w: literals run past the chunk", ErrFormat)
			}
			d.out = append(d.out, d.src[d.data])
			d.data++
		} else {
			// The period may reach back into an earlier chunk.
			if d.prewritten+d.written < d.period {
				return fmt.Errorf("%w: period %d reaches before the output", ErrFormat, d.period)
			}
			d.out = append(d.out, d.out[len(d.out)-d.period])
		}
		d.written++
	}
	return nil
}
