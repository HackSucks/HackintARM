package lzbitmap

import (
	"encoding/binary"
	"math/bits"
)

// Native mode 2 hashes four-byte words into overlapping pairs of 16-bit
// positions. The extra eight entries retain the vector implementation's guard.
func (e *encoder) nativeHistory() {
	if e.history != nil {
		return
	}
	e.history = make([]uint16, (1<<18)+8)
	for i := range e.history {
		e.history[i] = 8
	}
}
func (e *encoder) nativeBitmap(period, n int) uint16 {
	var bitmap uint16
	for i := 0; i < n; i++ {
		if e.src[e.pos+i] != e.src[e.pos-period+i] {
			bitmap |= 1 << i
		}
	}
	return bitmap
}
func (e *encoder) nativeEmit(bitmap byte, period, n int) {
	e.appendBitmap(bitmap, period)
	for i := 0; i < n; i++ {
		if bitmap&(1<<i) != 0 {
			e.lit = append(e.lit, e.src[e.pos+i])
		}
	}
	e.pos += n
}
func (e *encoder) nativeEightBytes() {
	var keys [8]uint32
	var history [8][2]uint16
	for lane := range keys {
		keys[lane] = (binary.LittleEndian.Uint32(e.src[e.pos+lane:]) * 2654435761) >> 14
		history[lane] = [2]uint16{e.history[keys[lane]], e.history[keys[lane]+1]}
	}
	// Snapshot candidates before inserting: overlapping hash slots make native
	// lane order observable in the encoded stream.
	for _, lane := range [...]int{1, 2, 3, 5, 6, 7, 4, 0} {
		at := keys[lane]
		e.history[at+1] = e.history[at]
		e.history[at] = uint16(e.pos + lane)
	}
	previous := e.nativeBitmap(e.period, 8)
	if previous == 0 {
		e.nativeEmit(0, e.period, 8)
		return
	}
	previous = e.nativeBitmap(e.period, 16)
	bestCost := 4*bits.OnesCount8(byte(previous)) + bits.OnesCount8(byte(previous>>8))
	var periods [16]int
	var bitmaps [16]uint16
	var costs [16]int
	perfect := false
	for rank, lane := range [...]int{0, 4, 2, 3, 1, 5, 6, 7} {
		for slot := 0; slot < 2; slot++ {
			i := rank + slot*8
			period := int(uint16(e.pos + lane - int(history[lane][slot])))
			periods[i] = period
			bitmap := uint16(0xffff)
			if period >= 8 && period <= e.pos {
				bitmap = e.nativeBitmap(period, 16)
			}
			bitmaps[i] = bitmap
			bytes := 1
			if period > 255 {
				bytes = 2
			}
			costs[i] = 4*(bits.OnesCount8(byte(bitmap))+bytes) + bits.OnesCount8(byte(bitmap>>8))
			if bitmap == 0 {
				perfect = true
			}
		}
	}
	// A selected exact 16-byte match receives the native four-point reward
	// during subsequent comparisons; equal scores retain the earlier choice.
	best := -1
	reward := 0
	for i, cost := range costs {
		if perfect {
			cost -= reward
		}
		if cost < bestCost {
			best, bestCost = i, cost
			if bitmaps[i] == 0 {
				reward = 4
			} else {
				reward = 0
			}
		}
	}
	if best < 0 {
		e.nativeEmit(byte(previous), e.period, 8)
	} else {
		e.nativeEmit(byte(bitmaps[best]), periods[best], 8)
	}
}
