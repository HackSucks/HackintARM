package lzbitmap

import (
	"bytes"
	"testing"
)

func TestLimitsAndMalformed(t *testing.T) {
	plain := bytes.Repeat([]byte("native compression"), 4000)
	encoded, err := Compress(plain)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecompressLimit(encoded, len(plain)); err != nil || !bytes.Equal(got, plain) {
		t.Fatal(err)
	}
	for _, limit := range []int{-1, 0, len(plain) - 1} {
		if _, err := DecompressLimit(encoded, limit); err == nil {
			t.Fatal("limit accepted", limit)
		}
	}
	for _, b := range [][]byte{nil, []byte("oops"), []byte(Magic), append([]byte(Magic), 0, 0, 0, 1, 0, 0), append([]byte(Magic), 6, 0, 0, 1, 128, 0)} {
		if _, err := Decompress(b); err == nil {
			t.Fatal("malformed stream accepted")
		}
	}
	if _, err := (&decoder{}).readNibble(); err == nil {
		t.Fatal("missing nibble")
	}
	if err := (&decoder{}).oneBitmap(); err == nil {
		t.Fatal("missing bitmap")
	}
	for _, d := range []*decoder{{src: []byte{0}, end: 1, decmpLen: 16}, {src: []byte{0xf0}, end: 1, decmpLen: 16}, {src: []byte{0xff}, end: 1, decmpLen: 16}} {
		if err := d.oneBitmap(); err == nil {
			t.Fatal("incomplete bitmap")
		}
	}
	for _, length := range []int{6, 15} {
		d := &decoder{src: make([]byte, 32), end: 32}
		if err := d.compressedChunk(length); err == nil {
			t.Fatal("short compressed header")
		}
	}
	d := &decoder{src: make([]byte, 32), end: 32}
	putU24(d.src[6:], 32)
	if err := d.compressedChunk(32); err == nil {
		t.Fatal("invalid meta offset")
	}
	d = &decoder{src: bytes.Repeat([]byte{0xff}, 32), end: 32}
	if err := d.readBitmaps(32); err == nil {
		t.Fatal("invalid period length")
	}
	if err := (&decoder{}).applyNumber(15); err == nil {
		t.Fatal("marker as bitmap")
	}
	if err := (&decoder{}).applyNumber(0); err == nil {
		t.Fatal("missing bitmap data")
	}
	if err := (&decoder{}).apply(bmap{}); err == nil {
		t.Fatal("zero period")
	}
	if err := (&decoder{}).apply(bmap{periodBytes: 1}); err == nil {
		t.Fatal("missing period")
	}
	if err := (&decoder{period: 1, decmpLen: 1}).apply(bmap{bitmap: 1}); err == nil {
		t.Fatal("missing literal")
	}
	if err := (&decoder{period: 1, decmpLen: 1}).apply(bmap{}); err == nil {
		t.Fatal("invalid back reference")
	}
	d = &decoder{src: bytes.Repeat([]byte{0xff}, 40000), end: 40000, decmpLen: 100}
	if _, err := d.repetitionCount(); err == nil {
		t.Fatal("excessive repeat")
	}
}
