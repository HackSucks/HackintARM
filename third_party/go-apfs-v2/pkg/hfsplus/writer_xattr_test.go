package hfsplus

import (
	"bytes"
	"os"
	"testing"
)

// TestWriteXattrs round-trips extended attributes through the writer and back
// through this package's reader, covering both record shapes: a value small
// enough to sit inside its own record, and one that needs an allocation extent.
func TestWriteXattrs(t *testing.T) {
	small := []byte("value42")
	finder := bytes.Repeat([]byte{0xAB}, 32)
	// Native HFS hides document ID, date-added and generation words.
	wantFinder := bytes.Clone(finder)
	clear(wantFinder[16:24])
	clear(wantFinder[28:32])
	// Comfortably past the inline ceiling at any node size this writer uses.
	large := bytes.Repeat([]byte("large attribute value. "), 500)

	root := &Entry{
		Xattrs: map[string][]byte{"com.example.root": []byte("on the root folder")},
		Children: []*Entry{
			{Name: "plain.txt", Mode: 0o644, Data: []byte("no attributes\n")},
			{Name: "small.txt", Mode: 0o644, Data: []byte("small\n"), Xattrs: map[string][]byte{
				"com.example.test":     small,
				"com.apple.FinderInfo": finder,
			}},
			{Name: "large.txt", Mode: 0o644, Data: []byte("large\n"), Xattrs: map[string][]byte{
				"com.example.big": large,
			}},
			{Name: "dir", Mode: os.ModeDir | 0o755, Xattrs: map[string][]byte{
				"com.example.dir": []byte("directories carry them too"),
			}},
		},
	}

	w := &memWriterAt{}
	if err := CreateImage(w, 0, "XATTR", root, nil); err != nil {
		t.Fatalf("CreateImage: %v", err)
	}

	v, err := New(bytes.NewReader(w.b))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, tc := range []struct {
		path, name string
		want       []byte
	}{
		{"small.txt", "com.example.test", small},
		{"small.txt", "com.apple.FinderInfo", wantFinder},
		{"large.txt", "com.example.big", large},
		{"dir", "com.example.dir", []byte("directories carry them too")},
		{".", "com.example.root", []byte("on the root folder")},
	} {
		attrs, err := v.Xattrs(tc.path)
		if err != nil {
			t.Errorf("Xattrs(%s): %v", tc.path, err)
			continue
		}
		got, ok := attrs[tc.name]
		if !ok {
			t.Errorf("%s: attribute %q was not written", tc.path, tc.name)
			continue
		}
		if !bytes.Equal(got, tc.want) {
			t.Errorf("%s %s: %d bytes, want %d", tc.path, tc.name, len(got), len(tc.want))
		}
	}

	// A file with none must report none.
	attrs, err := v.Xattrs("plain.txt")
	if err != nil {
		t.Fatalf("Xattrs(plain.txt): %v", err)
	}
	if len(attrs) != 0 {
		t.Errorf("a file with no attributes reported %d", len(attrs))
	}

	// Data forks must be undisturbed by the attribute extents sharing the
	// data region.
	if got, err := v.ReadFile("large.txt"); err != nil || string(got) != "large\n" {
		t.Errorf("large.txt = %q, err=%v", got, err)
	}
}

// TestWriteXattrsDeterministic checks that attribute ordering does not depend
// on Go's map iteration order, which would cost the writer its reproducibility.
func TestWriteXattrsDeterministic(t *testing.T) {
	build := func() []byte {
		root := &Entry{Children: []*Entry{
			{Name: "f.txt", Mode: 0o644, Data: []byte("x\n"), Xattrs: map[string][]byte{
				"com.example.a": []byte("a"),
				"com.example.b": []byte("b"),
				"com.example.c": []byte("c"),
				"com.example.d": []byte("d"),
				"com.example.e": []byte("e"),
			}},
		}}
		w := &memWriterAt{}
		if err := CreateImage(w, 0, "DET", root, nil); err != nil {
			t.Fatalf("CreateImage: %v", err)
		}
		return w.b
	}
	for range 5 {
		if !bytes.Equal(build(), build()) {
			t.Fatal("two runs over the same attributes produced different images")
		}
	}
}

// TestWriteNoXattrsEmitsNoAttributesFile pins the decision that a volume with
// no attributes carries no attributes file at all, so images this writer
// produced before it could emit one stay byte-identical.
func TestWriteNoXattrsEmitsNoAttributesFile(t *testing.T) {
	root := &Entry{Children: []*Entry{
		{Name: "a.txt", Mode: 0o644, Data: []byte("a\n")},
	}}
	w := &memWriterAt{}
	if err := CreateImage(w, 0, "NOATTR", root, nil); err != nil {
		t.Fatalf("CreateImage: %v", err)
	}
	v, err := New(bytes.NewReader(w.b))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := v.Header().AttributesFile.TotalBlocks; got != 0 {
		t.Errorf("AttributesFile.TotalBlocks = %d, want 0 for a volume with no attributes", got)
	}
}
