package hfsplus

import (
	"bytes"
	"testing"
	"time"
)

// buildImage builds an image from root into memory and returns its bytes.
func buildImage(t *testing.T, root *Entry, opts *CreateOptions) []byte {
	t.Helper()
	w := &memWriterAt{}
	if err := CreateImage(w, 0, "REPRO", root, opts); err != nil {
		t.Fatalf("CreateImage: %v", err)
	}
	return w.b
}

// TestCreateImageDeterministic builds the same image twice and requires the two
// to be byte-identical. Before DefaultTime existed, a nil CreateOptions fell
// back to time.Now(), which reached the volume header's create, modify and
// checked dates, every catalog record's dates, and the FinderInfo volume
// identifier (an FNV hash over the name and that timestamp).
//
// HFS+ timestamps have one-second resolution, so on its own this test only
// catches wall-clock drift when two builds straddle a second boundary.
// TestCreateImageDefaultTime is the deterministic guard for that regression.
func TestCreateImageDeterministic(t *testing.T) {
	root, _ := sampleTree()
	fixed := time.Date(2022, time.July, 1, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		opts *CreateOptions
	}{
		{"nil options", nil},
		{"zero options", &CreateOptions{}},
		{"fixed time", &CreateOptions{FixedTime: fixed}},
		{"explicit volume uuid", &CreateOptions{
			FixedTime:  fixed,
			VolumeUUID: [16]byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04},
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first := buildImage(t, root, tc.opts)
			second := buildImage(t, root, tc.opts)
			if !bytes.Equal(first, second) {
				t.Fatalf("two builds of the same image differ (%d vs %d bytes)", len(first), len(second))
			}
		})
	}
}

// TestCreateImageDefaultTime confirms an unset FixedTime resolves to
// DefaultTime rather than the wall clock.
func TestCreateImageDefaultTime(t *testing.T) {
	root, _ := sampleTree()
	if !bytes.Equal(buildImage(t, root, nil), buildImage(t, root, &CreateOptions{FixedTime: DefaultTime})) {
		t.Fatal("an unset FixedTime does not match an explicit DefaultTime")
	}
}

// TestCreateImageFixedTimeIsWired proves two builds differing only in
// FixedTime produce different bytes.
func TestCreateImageFixedTimeIsWired(t *testing.T) {
	root, _ := sampleTree()
	early := buildImage(t, root, &CreateOptions{FixedTime: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)})
	late := buildImage(t, root, &CreateOptions{FixedTime: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)})
	if bytes.Equal(early, late) {
		t.Fatal("images built with different FixedTime are byte-identical; FixedTime is not reaching the image")
	}
}

// TestCreateImageVolumeUUID checks an explicit VolumeUUID lands in
// FinderInfo[6] and FinderInfo[7] big-endian, and that a different UUID
// produces different bytes.
func TestCreateImageVolumeUUID(t *testing.T) {
	root, _ := sampleTree()
	fixed := time.Date(2022, time.July, 1, 12, 0, 0, 0, time.UTC)
	uuid := [16]byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}

	img := buildImage(t, root, &CreateOptions{FixedTime: fixed, VolumeUUID: uuid})

	v, err := New(bytes.NewReader(img))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	vh := v.Header()
	if vh.FinderInfo[6] != 0xdeadbeef {
		t.Errorf("FinderInfo[6] = %#08x, want 0xdeadbeef", vh.FinderInfo[6])
	}
	if vh.FinderInfo[7] != 0x01020304 {
		t.Errorf("FinderInfo[7] = %#08x, want 0x01020304", vh.FinderInfo[7])
	}

	other := uuid
	other[0] = 0x00
	if bytes.Equal(img, buildImage(t, root, &CreateOptions{FixedTime: fixed, VolumeUUID: other})) {
		t.Error("images built with different VolumeUUID are byte-identical")
	}
}

// TestCreateImageClampsModTimes checks the SOURCE_DATE_EPOCH rule: with
// ClampModTimes set, an entry newer than FixedTime is written as FixedTime and
// an older entry keeps its own time. Without it, the newer time survives.
func TestCreateImageClampsModTimes(t *testing.T) {
	fixed := time.Date(2022, time.July, 1, 12, 0, 0, 0, time.UTC)
	newer := fixed.Add(1 * time.Hour)
	older := fixed.Add(-1 * time.Hour)

	tree := func() *Entry {
		return &Entry{Children: []*Entry{
			{Name: "newer.txt", Mode: 0o644, Data: []byte("from the future\n"), ModTime: newer},
			{Name: "older.txt", Mode: 0o644, Data: []byte("from the past\n"), ModTime: older},
			{Name: "undated.txt", Mode: 0o644, Data: []byte("no time\n")},
		}}
	}

	check := func(t *testing.T, opts *CreateOptions, wantNewer time.Time) {
		t.Helper()
		img := buildImage(t, tree(), opts)
		vol, err := New(bytes.NewReader(img))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		for name, want := range map[string]time.Time{
			"newer.txt":   wantNewer,
			"older.txt":   older,
			"undated.txt": fixed,
		} {
			info, err := vol.Stat(name)
			if err != nil {
				t.Fatalf("Stat(%q): %v", name, err)
			}
			if got := info.ModTime().UTC(); !got.Equal(want.UTC()) {
				t.Errorf("%s: mod time = %s, want %s", name, got, want.UTC())
			}
		}
	}

	t.Run("clamped", func(t *testing.T) {
		check(t, &CreateOptions{FixedTime: fixed, ClampModTimes: true}, fixed)
	})
	t.Run("unclamped", func(t *testing.T) {
		check(t, &CreateOptions{FixedTime: fixed}, newer)
	})
}
