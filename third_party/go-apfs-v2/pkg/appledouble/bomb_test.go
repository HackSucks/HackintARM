package appledouble

import (
	"encoding/binary"
	"strings"
	"testing"
)

// The native two-entry profile rejects repeated resource-entry tables before
// copying their aliased data.
func TestDecodeResourceEntryAliasingBounded(t *testing.T) {
	const n = 3
	const dataLen = 100
	total := 26 + 12*n + dataLen
	b := make([]byte, total)
	binary.BigEndian.PutUint32(b[0:], magic)
	binary.BigEndian.PutUint32(b[4:], version)
	binary.BigEndian.PutUint16(b[24:], n)
	dataOff := 26 + 12*n
	for i := 0; i < n; i++ {
		e := b[26+12*i:]
		binary.BigEndian.PutUint32(e[0:], entryResource)
		binary.BigEndian.PutUint32(e[4:], uint32(dataOff))
		binary.BigEndian.PutUint32(e[8:], uint32(dataLen))
	}
	// n*dataLen = 300 > total (162): the aliased copies exceed the file.
	if _, err := Decode(b); err == nil {
		t.Fatal("aliased resource entries were accepted; cumulative copy is unbounded")
	}
}

// TestDecodeAttrAliasingBounded pins F4 (attribute-value variant): many
// attribute entries each pointing at the same near-whole-file region must be
// rejected rather than each retained.
func TestDecodeAttrAliasingBounded(t *testing.T) {
	const numAttrs = 3
	const valLen = 100
	finderOff := 50
	attrOff := 84
	hdrLen := 36
	entriesOff := attrOff + hdrLen
	total := entriesOff + numAttrs*16
	b := make([]byte, total)
	binary.BigEndian.PutUint32(b[0:], magic)
	binary.BigEndian.PutUint32(b[4:], version)
	binary.BigEndian.PutUint16(b[24:], 2)
	binary.BigEndian.PutUint32(b[38:], entryResource)
	e := b[26:]
	binary.BigEndian.PutUint32(e[0:], entryFinder)
	binary.BigEndian.PutUint32(e[4:], uint32(finderOff))
	binary.BigEndian.PutUint32(e[8:], uint32(total-finderOff))
	copy(b[attrOff:], attrMagic)
	binary.BigEndian.PutUint32(b[attrOff+8:], uint32(total)) // totalSize <= len(b)
	binary.BigEndian.PutUint16(b[attrOff+34:], numAttrs)
	for i := 0; i < numAttrs; i++ {
		ae := b[entriesOff+16*i:]
		binary.BigEndian.PutUint32(ae[0:], 0)      // valOff: all alias offset 0
		binary.BigEndian.PutUint32(ae[4:], valLen) // valLen
		ae[10] = 2                                 // valid, terminated names so this reaches the copy budget
		ae[11] = byte('a' + i)
	}
	// numAttrs*valLen = 300 > total (168): reach the allocation guard.
	if _, err := Decode(b); err == nil || !strings.Contains(err.Error(), "copied data exceeds") {
		t.Fatal("did not reach cumulative allocation guard", err)
	}
}
