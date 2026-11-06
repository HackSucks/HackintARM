package hfsplus

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"strings"
	"testing"
)

// The HFS+ writer carries a compressed file's com.apple.decmpfs attribute
// through unchanged and sets UF_COMPRESSED to match. Unlike the APFS side,
// this package's own reader dispatches on that flag (volume.go), so a round
// trip through it really does test whether the flag was written — read the
// content back and a missing flag gives an empty file, not the right bytes.

const hfsDecmpfsPayload = "the quick brown fox jumps over the lazy dog, repeatedly and at length. " +
	"the quick brown fox jumps over the lazy dog, repeatedly and at length. " +
	"the quick brown fox jumps over the lazy dog, repeatedly and at length.\n"

func hfsDecmpfsHeader(kind uint32, size uint64) []byte {
	h := make([]byte, 16)
	copy(h, "fpmc")
	binary.LittleEndian.PutUint32(h[4:], kind)
	binary.LittleEndian.PutUint64(h[8:], size)
	return h
}

// hfsInlineDecmpfs is a type-3 attribute: zlib, payload inline after the header.
func hfsInlineDecmpfs(payload string) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write([]byte(payload))
	w.Close()
	return append(hfsDecmpfsHeader(3, uint64(len(payload))), buf.Bytes()...)
}

func writeVolume(t *testing.T, root *Entry) *Volume {
	t.Helper()
	w := &memWriterAt{}
	if err := CreateImage(w, 0, "DECMPFS", root, nil); err != nil {
		t.Fatalf("CreateImage: %v", err)
	}
	v, err := New(bytes.NewReader(w.b))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

// TestWriteDecmpfsInlineRoundTrip is the point of the change: a compressed file
// written by this package reads back decompressed.
func TestWriteDecmpfsInlineRoundTrip(t *testing.T) {
	v := writeVolume(t, &Entry{Children: []*Entry{
		{Name: "squeezed.txt", Mode: 0o644, Xattrs: map[string][]byte{
			decmpfsAttrName: hfsInlineDecmpfs(hfsDecmpfsPayload),
		}},
		{Name: "plain.txt", Mode: 0o644, Data: []byte("not compressed\n")},
	}})

	got, err := v.ReadFile("squeezed.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != hfsDecmpfsPayload {
		t.Errorf("read %d bytes, want %d; an empty read means UF_COMPRESSED was not written",
			len(got), len(hfsDecmpfsPayload))
	}

	if plain, err := v.ReadFile("plain.txt"); err != nil || string(plain) != "not compressed\n" {
		t.Errorf("plain.txt = %q, %v", plain, err)
	}
}

// TestWriteDecmpfsSetsTheCompressedFlag checks the flag directly, so a failure
// says which of the two halves broke rather than only that the read was empty.
func TestWriteDecmpfsSetsTheCompressedFlag(t *testing.T) {
	v := writeVolume(t, &Entry{Children: []*Entry{
		{Name: "squeezed.txt", Mode: 0o644, Xattrs: map[string][]byte{
			decmpfsAttrName: hfsInlineDecmpfs(hfsDecmpfsPayload),
		}},
		{Name: "plain.txt", Mode: 0o644, Data: []byte("nothing special\n")},
	}})

	for name, wantCompressed := range map[string]bool{
		"squeezed.txt": true,
		"plain.txt":    false,
	} {
		e, err := v.lookup(name)
		if err != nil {
			t.Fatalf("lookup(%q): %v", name, err)
		}
		got := e.file.BSDInfo.OwnerFlags&ufCompressed != 0
		if got != wantCompressed {
			t.Errorf("%s: UF_COMPRESSED = %v, want %v (OwnerFlags = %#x)",
				name, got, wantCompressed, e.file.BSDInfo.OwnerFlags)
		}
	}
}

// TestWriteDecmpfsIsDeterministic keeps the byte-for-byte reproducibility the
// writer promises.
func TestWriteDecmpfsIsDeterministic(t *testing.T) {
	build := func() []byte {
		w := &memWriterAt{}
		err := CreateImage(w, 0, "DET", &Entry{Children: []*Entry{
			{Name: "squeezed.txt", Mode: 0o644, Xattrs: map[string][]byte{
				decmpfsAttrName: hfsInlineDecmpfs(hfsDecmpfsPayload),
			}},
		}}, nil)
		if err != nil {
			t.Fatalf("CreateImage: %v", err)
		}
		return w.b
	}
	if !bytes.Equal(build(), build()) {
		t.Error("two runs over the same compressed file produced different images")
	}
}

// TestWriteRejectsInconsistentDecmpfs covers the validation this writer had
// none of. Before, a hand-built Entry with a decmpfs attribute was written with
// the compression flag clear: a file claiming compressed content in its
// attribute and denying it in its mode.
func TestWriteRejectsInconsistentDecmpfs(t *testing.T) {
	forkHeader := hfsDecmpfsHeader(4, uint64(len(hfsDecmpfsPayload))) // type 4 keeps data in the fork

	cases := []struct {
		name     string
		entry    Entry
		contains string
	}{
		{
			"content in the data fork as well",
			Entry{Name: "both.txt", Mode: 0o644, Data: []byte("a data fork too\n"),
				Xattrs: map[string][]byte{decmpfsAttrName: hfsInlineDecmpfs(hfsDecmpfsPayload)}},
			"empty data fork",
		},
		{
			"a fork-based type with no resource fork",
			Entry{Name: "missing.txt", Mode: 0o644,
				Xattrs: map[string][]byte{decmpfsAttrName: forkHeader}},
			"which is absent",
		},
		{
			"an attribute with no fpmc header",
			Entry{Name: "headerless.txt", Mode: 0o644,
				Xattrs: map[string][]byte{decmpfsAttrName: []byte("not a decmpfs attribute")}},
			"does not begin with",
		},
		{
			// On HFS+ a resource fork is a fork of the catalog record, not an
			// entry in the attributes file. Accepting it in Xattrs would write
			// the content twice and disagree with what a reader reports.
			"a resource fork passed as an attribute",
			Entry{Name: "wrongplace.txt", Mode: 0o644,
				Xattrs: map[string][]byte{"com.apple.ResourceFork": []byte("fork bytes")}},
			"belongs in Entry.ResourceFork",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry := tc.entry
			err := CreateImage(&memWriterAt{}, 0, "BAD", &Entry{Children: []*Entry{&entry}}, nil)
			if err == nil {
				t.Fatal("CreateImage accepted an inconsistent compressed file")
			}
			if !strings.Contains(err.Error(), tc.contains) {
				t.Errorf("error = %q, want it to mention %q", err, tc.contains)
			}
		})
	}
}
