package disk

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"strings"
	"testing"
)

// gptImage builds a two-sector image holding a protective sector and a GPT
// header whose partition-entry count is entries, with no entries behind it.
func gptImage(t testing.TB, entries uint32) []byte {
	t.Helper()
	h := GPTHeader{
		Revision:       0x00010000,
		HeaderSize:     gptSectorSize - 420,
		HeaderStartLBA: 1,
		EntriesStart:   2,
		EntriesCount:   entries,
		EntriesSize:    128,
	}
	copy(h.Signature[:], gptSignature)
	var buf bytes.Buffer
	buf.Write(make([]byte, gptSectorSize))
	if err := binary.Write(&buf, binary.LittleEndian, &h); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestGPTEntriesCountBounded checks that a raw image's GPT header cannot make
// the opener allocate an arbitrary partition table. Before the entry count
// was bounded, a 1 KiB image claiming 1<<20 entries made findAPFSPartitionInGPT
// allocate 128 MiB, and 0xFFFFFFFF entries asked for about 512 GiB.
func TestGPTEntriesCountBounded(t *testing.T) {
	for _, entries := range []uint32{gptMaxEntries + 1, 1 << 20, 0xFFFFFFFF} {
		img := gptImage(t, entries)

		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_, err := findAPFSPartitionInGPT(bytes.NewReader(img))
		runtime.ReadMemStats(&after)

		if err == nil || !strings.Contains(err.Error(), "partition entries") {
			t.Fatalf("%d entries: err = %v, want the entry-count bound", entries, err)
		}
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1<<20 {
			t.Fatalf("%d entries: allocated %d bytes for a %d-byte image", entries, allocated, len(img))
		}
	}
}

// TestGPTEntriesCountAtBound checks the largest permitted table is still
// read: the header is accepted and the missing entries are what fail.
func TestGPTEntriesCountAtBound(t *testing.T) {
	_, err := findAPFSPartitionInGPT(bytes.NewReader(gptImage(t, gptMaxEntries)))
	if err == nil || !strings.Contains(err.Error(), "unable to read GPT partition entries") {
		t.Fatalf("err = %v, want a failure reading the (absent) entries", err)
	}
}
