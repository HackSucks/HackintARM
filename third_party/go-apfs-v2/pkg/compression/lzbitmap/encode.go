package lzbitmap

import "math"

// Encoding uses the native bounded hash matcher and descriptor ordering. Each
// chunk covers at most MaxChunk bytes; eight-byte groups refer to earlier input
// using a bitmap of differing bytes and a one- or two-byte period. The matcher
// examines at most sixteen history candidates, independent of input length.
// Twelve selected descriptors use compact nibble codes; other descriptors are
// inline. Chunks that do not shrink are stored verbatim.
const (
	possibleBitmaps = 1 << 10
	initialPeriod   = 8
)

// bmprot indexes the use counter for a descriptor.
func bmprot(b bmap) int { return int(b.bitmap)<<2 | int(b.periodBytes) }

type encoder struct {
	room    int // remaining destination bytes before the native 31-byte safety margin
	history []uint16
	src     []byte
	pos     int // next byte of src to consume, across all chunks

	// Per chunk.
	decmpLen int
	start    int // pos at the start of the chunk
	period   int
	bitmaps  []bmap
	periods  []int
	lit      []byte
	usecnts  [possibleBitmaps]int
	top      [bitmapCount]bmap
}

// Compress encodes src as an LZBITMAP stream.
func Compress(src []byte) ([]byte, error) {
	e := &encoder{src: src, room: math.MaxInt}
	out := make([]byte, 0, len(src)/2+64)
	out = append(out, Magic...)
	for {
		chunk := e.chunk()
		out = append(out, chunk...)
		if e.decmpLen == 0 {
			return out, nil
		}
	}
}

// chunk encodes the next chunk, returning its bytes. The final chunk is
// an empty one, which is how a stream ends.
func (e *encoder) chunk() []byte {
	e.start = e.pos
	e.decmpLen = len(e.src) - e.pos
	if e.decmpLen > MaxChunk {
		e.decmpLen = MaxChunk
	}
	if c := e.compressed(); c != nil && len(c) < e.decmpLen+chunkHdrSize {
		e.pos = e.start + e.decmpLen
		return c
	}
	// Not worth compressing: a plain header and the bytes themselves.
	out := make([]byte, chunkHdrSize, chunkHdrSize+e.decmpLen)
	putU24(out[0:], chunkHdrSize+e.decmpLen)
	putU24(out[3:], e.decmpLen)
	out = append(out, e.src[e.start:e.start+e.decmpLen]...)
	e.pos = e.start + e.decmpLen
	return out
}

// compressed builds the compressed form of the current chunk, or nil if
// the chunk is too short for one.
func (e *encoder) compressed() []byte {
	if e.decmpLen <= 144 || e.room < 15 {
		return nil
	}
	e.bitmaps = e.bitmaps[:0]
	e.periods = e.periods[:0]
	e.lit = e.lit[:0]
	e.usecnts = [possibleBitmaps]int{}
	e.top = [bitmapCount]bmap{}
	e.pos = e.start

	if e.start == 0 {
		// The first eight bytes of a stream have nothing to refer back
		// to, so they are literals under a bitmap of all ones.
		e.bitmaps = append(e.bitmaps, bmap{bitmap: 0xff})
		e.periods = append(e.periods, 0)
		e.usecnts[bmprot(bmap{bitmap: 0xff})] = 1
		e.lit = append(e.lit, e.src[e.pos:e.pos+8]...)
		e.pos += 8
	}
	e.period = initialPeriod

	e.nativeHistory()
	fastEnd := e.start + max(0, (min(e.start+e.decmpLen, len(e.src)-16)-e.start)/128)*128
	for group := e.start; group < fastEnd; group += 128 {
		literals := len(e.lit)
		if group == 0 {
			literals -= 8
		}
		if 15+literals+128 > e.room {
			return nil
		}
		for e.pos < group+128 {
			e.nativeEightBytes()
		}
	}
	// The scalar tail reserves literal space through the next 64-byte boundary
	// before it knows which bytes will match the current period.
	if 15+len(e.lit)+((e.decmpLen+63)&^63)-(e.pos-e.start) > e.room {
		return nil
	}

	for e.pos < e.start+e.decmpLen {
		n := min(8, e.start+e.decmpLen-e.pos)
		e.nativeEmit(byte(e.nativeBitmap(e.period, n)), e.period, n)
	}
	for len(e.bitmaps)%8 != 0 {
		e.bitmaps = append(e.bitmaps, bmap{})
		e.periods = append(e.periods, 0)
		e.usecnts[0]++
	}
	return e.assemble()
}

// appendBitmap records a descriptor and the period it introduces.
func (e *encoder) appendBitmap(bitmap byte, period int) {
	b := bmap{bitmap: bitmap}
	switch {
	case period == e.period:
		b.periodBytes = 0
	case period <= 0xff:
		b.periodBytes = 1
	default:
		b.periodBytes = 2
	}
	e.bitmaps = append(e.bitmaps, b)
	e.periods = append(e.periods, period)
	e.usecnts[bmprot(b)]++
	e.period = period
}

// chooseTop retains the native histogram order when twelve descriptors suffice.
// For larger alphabets, partition packed frequency/descriptor words around the
// twelfth greatest entry; the selected prefix is deliberately not fully sorted.
func (e *encoder) chooseTop() {
	var words []uint32
	for id := 0; id < possibleBitmaps; id++ {
		b := bmap{bitmap: byte(id), periodBytes: byte(id >> 8)}
		count := e.usecnts[bmprot(b)]
		if count > 0 {
			words = append(words, uint32(count)<<16|uint32(id))
		}
	}
	if len(words) > bitmapCount {
		low, high := 0, len(words)
		for {
			last, mid := high-1, (low+high)/2
			if words[low] > words[last] {
				words[low], words[last] = words[last], words[low]
			}
			if words[mid] > words[last] {
				words[mid], words[last] = words[last], words[mid]
			}
			if words[mid] > words[low] {
				words[mid], words[low] = words[low], words[mid]
			}
			pivot := words[low]
			i, j := low, high-1
			for {
				for words[i] > pivot {
					i++
				}
				for words[j] < pivot {
					j--
				}
				if i >= j {
					break
				}
				words[i], words[j] = words[j], words[i]
				i++
				j--
			}
			split := j + 1
			if split == bitmapCount {
				break
			}
			if split < bitmapCount {
				low = split
			} else {
				high = split
			}
		}
	}
	for i := 0; i < min(bitmapCount, len(words)); i++ {
		id := words[i] & 0xffff
		b := bmap{bitmap: byte(id), periodBytes: byte(id >> 8)}
		e.top[i] = b
		e.usecnts[bmprot(b)] = 0
	}
}

// numberFor is the nibble naming a descriptor: an index into the trailing
// bitmaps for a common one, or its period byte count for an inline one.
func (e *encoder) numberFor(i int) byte {
	b := e.bitmaps[i]
	if e.usecnts[bmprot(b)] == 0 {
		for j := 0; j < bitmapCount; j++ {
			if e.top[j] == b {
				return byte(j + bitmapBase)
			}
		}
	}
	return b.periodBytes
}

// assemble lays the chunk out: header, literals, the three metadata
// areas, then the trailing bitmaps.
func (e *encoder) assemble() []byte {
	e.chooseTop()

	// The periods, whenever one changes.
	var meta1 []byte
	for i, b := range e.bitmaps {
		if b.periodBytes == 0 {
			continue
		}
		meta1 = append(meta1, byte(e.periods[i]))
		if b.periodBytes == 2 {
			meta1 = append(meta1, byte(e.periods[i]>>8))
		}
	}

	// The descriptors that are not common enough to be named by index.
	var meta2 []byte
	for _, b := range e.bitmaps {
		if e.usecnts[bmprot(b)] != 0 {
			meta2 = append(meta2, b.bitmap)
		}
	}

	// The native encoder checks the uncollapsed nibble table before RLE.
	if 15+len(e.lit)+len(meta1)+len(meta2)+len(e.bitmaps)/2 > e.room {
		return nil
	}

	// The bitmap numbers, a nibble each, with runs collapsed.
	var meta3 []byte
	half := false
	put := func(v byte) {
		if !half {
			meta3 = append(meta3, v)
			half = true
		} else {
			meta3[len(meta3)-1] |= v << 4
			half = false
		}
	}
	for i := 0; i < len(e.bitmaps); {
		num := e.numberFor(i)
		repeat := 1
		for j := i + 1; j < len(e.bitmaps) && e.numberFor(j) == num; j++ {
			repeat++
		}
		put(num)
		if repeat <= 3 {
			for j := 1; j < repeat; j++ {
				put(num)
			}
		} else {
			// 0xf opens a count, which is nibbles summed onto a base of
			// four and must not end on 0xf.
			put(0xf)
			left := repeat - repeatBase
			last := byte(0xf)
			for left > 0 {
				last = byte(left)
				if left > 0xf {
					last = 0xf
				}
				put(last)
				left -= int(last)
			}
			if last == 0xf {
				put(0)
			}
		}
		i += repeat
	}

	trailing := make([]byte, bitmapByteCount)
	at, bit := 0, 0
	putBit := func(v byte) {
		trailing[at] |= v << bit
		bit++
		if bit == 8 {
			bit = 0
			at++
		}
	}
	for _, b := range e.top {
		for i := 0; i < 8; i++ {
			putBit(b.bitmap >> i & 1)
		}
		for i := 0; i < 2; i++ {
			putBit(b.periodBytes >> i & 1)
		}
	}

	off1 := cmpChunkHdrSize + len(e.lit)
	off2 := off1 + len(meta1)
	off3 := off2 + len(meta2)
	total := off3 + len(meta3) + bitmapByteCount

	out := make([]byte, cmpChunkHdrSize, total)
	putU24(out[0:], total)
	putU24(out[3:], e.decmpLen)
	putU24(out[6:], off1)
	putU24(out[9:], off2)
	putU24(out[12:], off3)
	out = append(out, e.lit...)
	out = append(out, meta1...)
	out = append(out, meta2...)
	out = append(out, meta3...)
	if len(out)+17 > e.room {
		return nil
	}
	out = append(out, trailing...)
	return out
}

// EncodeBuffer encodes into a bounded destination using native buffer-capacity
// decisions. It returns zero when the stream cannot fit, including the native
// 31-byte safety margin and intermediate literal/nibble reservations. On zero,
// destination contents are unspecified. Source and destination must not overlap.
func EncodeBuffer(dst, src []byte) int {
	if len(dst) < 35 {
		return 0
	}
	e := encoder{src: src}
	out := make([]byte, 0, min(len(dst), len(src)/2+64))
	out = append(out, Magic...)
	for {
		e.room = len(dst) - 31 - len(out)
		if e.room < chunkHdrSize {
			return 0
		}
		chunk := e.chunk()
		if len(chunk) > e.room {
			return 0
		}
		out = append(out, chunk...)
		if e.decmpLen == 0 {
			return copy(dst, out)
		}
	}
}
