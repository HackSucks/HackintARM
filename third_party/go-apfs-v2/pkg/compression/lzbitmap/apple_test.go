package lzbitmap

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

// The fixtures are their own pair rather than joining the aa-*.aar family
// that decodes to aa-raw.aar. That family was produced on another machine
// and its tree cannot be recreated byte for byte here, because macOS
// stamps files with a com.apple.provenance attribute that cannot be
// removed. A self-contained pair is just as good an reference: both halves
// come from Apple's aa, from one tree, in one run.
const (
	appleCompressed = "testdata/aa-lzbitmap.aar"
	applePlain      = "testdata/aa-lzbitmap-raw.aar"
)

// TestDecodesAppleOutput decodes the LZBITMAP chunks of an archive Apple's
// aa produced, and checks they come out as the same archive uncompressed.
func TestDecodesAppleOutput(t *testing.T) {
	pbzb, err := os.ReadFile(appleCompressed)
	if err != nil {
		t.Fatal("required native fixture missing:", err)
	}
	want, err := os.ReadFile(applePlain)
	if err != nil {
		t.Fatal("required native fixture missing:", err)
	}
	if string(pbzb[:4]) != "pbzb" {
		t.Fatalf("fixture is %q, not a pbzb container", pbzb[:4])
	}
	var got []byte
	for off := 12; off+16 <= len(pbzb); {
		inflated := binary.BigEndian.Uint64(pbzb[off:])
		deflated := binary.BigEndian.Uint64(pbzb[off+8:])
		off += 16
		if uint64(len(pbzb)-off) < deflated {
			t.Fatalf("chunk of %d bytes runs past the fixture", deflated)
		}
		block := pbzb[off : off+int(deflated)]
		off += int(deflated)
		if inflated == deflated { // stored, not compressed
			got = append(got, block...)
			continue
		}
		out, err := Decompress(block)
		if err != nil {
			t.Fatalf("decompress: %v", err)
		}
		if uint64(len(out)) != inflated {
			t.Fatalf("chunk decoded to %d bytes, the container says %d", len(out), inflated)
		}
		got = append(got, out...)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("decoded %d bytes, want %d", len(got), len(want))
	}
}

// TestCompressesLikeApple checks our encoder against Apple's on the same
// input: it must decode back, and it must not be much larger than what aa
// produced, which would mean the pattern search had gone wrong.
func TestCompressesLikeApple(t *testing.T) {
	plain, err := os.ReadFile(applePlain)
	if err != nil {
		t.Fatal("required native fixture missing:", err)
	}
	theirs, err := os.ReadFile(appleCompressed)
	if err != nil {
		t.Fatal("required native fixture missing:", err)
	}
	ours, err := Compress(plain)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decompress(ours)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, plain) {
		t.Fatal("our own output does not decode back")
	}
	// Apple's container adds 12 bytes of pbzb header plus 16 per chunk;
	// compare the payloads loosely, within a tenth.
	if limit := len(theirs) + len(theirs)/10; len(ours) > limit {
		t.Errorf("compressed to %d bytes, aa managed %d", len(ours), len(theirs))
	}
	t.Logf("ours %d bytes, aa %d", len(ours), len(theirs))
}
