// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite_test

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// A decmpfs-compressed file keeps its content in com.apple.decmpfs (inline) or
// com.apple.ResourceFork (chunked), and its data fork is empty. The writer
// carries those attributes through unchanged rather than compressing anything
// itself, and owes them one thing: UF_COMPRESSED in bsd_flags.
//
// Getting that flag wrong is invisible to everything except a real mount. With
// the attribute present and the flag clear, fsck_apfs reports the volume clean
// and this package's own reader returns the right bytes, but macOS reports the
// file as 0 bytes and empty. apfsck does catch it, which is what makes the
// acceptance tests worth having.

const decmpfsPayload = "the quick brown fox jumps over the lazy dog, repeatedly and at length. " +
	"the quick brown fox jumps over the lazy dog, repeatedly and at length. " +
	"the quick brown fox jumps over the lazy dog, repeatedly and at length.\n"

// decmpfsHeader builds the 16-byte fpmc header every decmpfs attribute starts
// with.
func decmpfsHeader(kind uint32, size uint64) []byte {
	h := make([]byte, 16)
	copy(h, "fpmc")
	binary.LittleEndian.PutUint32(h[4:], kind)
	binary.LittleEndian.PutUint64(h[8:], size)
	return h
}

func zlibBytes(b []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

// inlineDecmpfs is a type-3 attribute: zlib, payload inline after the header.
func inlineDecmpfs(payload string) []byte {
	return append(decmpfsHeader(3, uint64(len(payload))), zlibBytes([]byte(payload))...)
}

// TestCreateContainerDecmpfsInlineRoundTrip writes a compressed file and reads
// it back decompressed, which is what a reader is owed.
func TestCreateContainerDecmpfsInlineRoundTrip(t *testing.T) {
	vol := openVolume(t, &apfswrite.CreateOptions{
		VolumeName: "DECMPFS",
		Root: &apfswrite.Entry{Children: []*apfswrite.Entry{
			{Name: "plain.txt", Data: []byte("not compressed\n")},
			{Name: "squeezed.txt", Xattrs: map[string][]byte{
				"com.apple.decmpfs": inlineDecmpfs(decmpfsPayload),
			}},
		}},
	})

	got, err := vol.ReadFile("squeezed.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != decmpfsPayload {
		t.Errorf("read %d bytes, want %d", len(got), len(decmpfsPayload))
	}

	// The uncompressed file alongside it must be unaffected.
	if plain, err := vol.ReadFile("plain.txt"); err != nil || string(plain) != "not compressed\n" {
		t.Errorf("plain.txt = %q, %v", plain, err)
	}
}

// TestCreateContainerDecmpfsSetsCompressedFlag is the assertion the round trip
// cannot make: this package's reader dispatches on the attribute being present,
// not on bsd_flags, so it returns the right bytes either way. macOS does the
// opposite and returns nothing at all when the flag is missing.
func TestCreateContainerDecmpfsSetsCompressedFlag(t *testing.T) {
	vol := openVolume(t, &apfswrite.CreateOptions{
		VolumeName: "DECMPFS",
		Root: &apfswrite.Entry{Children: []*apfswrite.Entry{
			{Name: "squeezed.txt", Xattrs: map[string][]byte{
				"com.apple.decmpfs": inlineDecmpfs(decmpfsPayload),
			}},
			{Name: "plain.txt", Data: []byte("nothing special\n")},
		}},
	})

	for _, tc := range []struct {
		name           string
		wantCompressed bool
	}{
		{"squeezed.txt", true},
		{"plain.txt", false},
	} {
		entry, err := vol.FileEntryByPath(tc.name)
		if err != nil {
			t.Fatalf("FileEntryByPath(%q): %v", tc.name, err)
		}
		flags, err := entry.BSDFlags()
		if err != nil {
			t.Fatalf("BSDFlags(%q): %v", tc.name, err)
		}
		if got := flags&apfs.BSDFlagCompressed != 0; got != tc.wantCompressed {
			t.Errorf("%s: UF_COMPRESSED = %v, want %v (bsd_flags = %#x)",
				tc.name, got, tc.wantCompressed, flags)
		}
	}
}

// TestCreateContainerDecmpfsIsDeterministic keeps the byte-for-byte
// reproducibility the writer promises.
func TestCreateContainerDecmpfsIsDeterministic(t *testing.T) {
	build := func() []byte {
		img := &memImage{}
		err := apfswrite.CreateContainer(img, 32*1024*1024, &apfswrite.CreateOptions{
			VolumeName: "DET",
			Root: &apfswrite.Entry{Children: []*apfswrite.Entry{
				{Name: "squeezed.txt", Xattrs: map[string][]byte{
					"com.apple.decmpfs": inlineDecmpfs(decmpfsPayload),
				}},
			}},
		})
		if err != nil {
			t.Fatalf("CreateContainer: %v", err)
		}
		return img.data
	}
	if !bytes.Equal(build(), build()) {
		t.Error("two runs over the same compressed file produced different images")
	}
}

// TestCreateContainerRejectsInconsistentDecmpfs covers the ways an attribute
// and the file carrying it can disagree. Each would produce a file that some
// reader gets wrong, so it is refused rather than written.
func TestCreateContainerRejectsInconsistentDecmpfs(t *testing.T) {
	forkHeader := decmpfsHeader(4, uint64(len(decmpfsPayload))) // type 4 keeps data in the fork

	cases := []struct {
		name     string
		entry    apfswrite.Entry
		contains string
	}{
		{
			// The content is in the attribute, so bytes in the data fork are a
			// second, contradictory copy that nothing would read.
			"content in the data fork as well",
			apfswrite.Entry{
				Name:   "both.txt",
				Data:   []byte("a data fork too\n"),
				Xattrs: map[string][]byte{"com.apple.decmpfs": inlineDecmpfs(decmpfsPayload)},
			},
			"empty data fork",
		},
		{
			"a fork-based type with no resource fork",
			apfswrite.Entry{
				Name:   "missing.txt",
				Xattrs: map[string][]byte{"com.apple.decmpfs": forkHeader},
			},
			"which is absent",
		},
		{
			"an attribute with no fpmc header",
			apfswrite.Entry{
				Name:   "headerless.txt",
				Xattrs: map[string][]byte{"com.apple.decmpfs": []byte("not a decmpfs attribute at all")},
			},
			"does not begin with",
		},
		{
			// Type 5 does not describe content; answering it with zeros is the
			// silent-wrong-answer bug this project removed from the reader.
			"a type that does not describe content",
			apfswrite.Entry{
				Name:   "dedup.txt",
				Xattrs: map[string][]byte{"com.apple.decmpfs": append(decmpfsHeader(5, 10), 1, 2, 3)},
			},
			"de-duplication",
		},
		{
			"an inline type carrying only a header",
			apfswrite.Entry{
				Name:   "empty.txt",
				Xattrs: map[string][]byte{"com.apple.decmpfs": decmpfsHeader(3, 10)},
			},
			"too short",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry := tc.entry
			err := apfswrite.CreateContainer(&memImage{}, 32*1024*1024, &apfswrite.CreateOptions{
				VolumeName: "BAD",
				Root:       &apfswrite.Entry{Children: []*apfswrite.Entry{&entry}},
			})
			if err == nil {
				t.Fatal("CreateContainer accepted an inconsistent compressed file")
			}
			if !strings.Contains(err.Error(), tc.contains) {
				t.Errorf("error = %q, want it to mention %q", err, tc.contains)
			}
		})
	}
}
