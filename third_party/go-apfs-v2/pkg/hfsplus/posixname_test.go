package hfsplus

import (
	"bytes"
	"io/fs"
	"os"
	"testing"
	"testing/fstest"
	"time"
)

// TestPOSIXNamesRoundTrip covers names whose POSIX spelling holds a colon.
// HFS+ stores the colon as a slash, so without the mapping the entry is listed
// with a slash inside one element and no path can open it.
func TestPOSIXNamesRoundTrip(t *testing.T) {
	names := []string{"Chasing Shadows Clap:Snare 01.loopdata", `1\16 Alternating Pan.pst`, "plain.txt", "x\u2400y", "\u2400"}
	children := make([]*Entry, 0, len(names))
	for _, name := range names {
		children = append(children, &Entry{Name: name, Mode: 0o644, Data: []byte(name)})
	}
	root := &Entry{Children: []*Entry{
		{Name: "Resources", Mode: os.ModeDir | 0o755, Children: children},
	}}
	w := &memWriterAt{}
	if err := CreateImage(w, 0, "Named", root, &CreateOptions{FixedTime: time.Unix(0, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	volume, err := New(bytes.NewReader(w.b))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		data, err := fs.ReadFile(volume, "Resources/"+name)
		if err != nil || string(data) != name {
			t.Fatalf("%q reads %q: %v", name, data, err)
		}
	}
	entries, err := fs.ReadDir(volume, "Resources")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !fs.ValidPath(entry.Name()) {
			t.Fatalf("listed %q is not a valid io/fs element", entry.Name())
		}
	}
	// fstest rejects a backslash in any name it walks, so the interface check
	// runs over a volume holding only the colon name.
	colons := &memWriterAt{}
	if err := CreateImage(colons, 0, "Named", &Entry{Children: []*Entry{{Name: names[0], Mode: 0o644, Data: []byte(names[0])}}}, &CreateOptions{FixedTime: time.Unix(0, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	checked, err := New(bytes.NewReader(colons.b))
	if err != nil {
		t.Fatal(err)
	}
	if err := fstest.TestFS(checked, names[0]); err != nil {
		t.Fatal(err)
	}
}

func TestAlternateNULCatalogEncoding(t *testing.T) {
	for _, insensitive := range []bool{false, true} {
		image := &memWriterAt{}
		if err := CreateImage(image, 0, "Names", &Entry{Children: []*Entry{{Name: "x\u2400y", Data: []byte("payload")}, {Name: "\u2400", Data: []byte("payload")}}}, &CreateOptions{CaseInsensitive: insensitive}); err != nil {
			t.Fatal(err)
		}
		volume, err := New(bytes.NewReader(image.b))
		if err != nil {
			t.Fatal(err)
		}
		found := map[string]bool{}
		if err = volume.catalogTree.walkLeaves(func(record leafRecord) error {
			parent, name, err := parseCatalogKey(record.key)
			if err != nil {
				return err
			}
			if parent == HFSRootFolderID && (name == "x\x00y" || name == "\x00") {
				found[name] = true
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if !found["x\x00y"] || !found["\x00"] {
			t.Fatal("native UTF16 NUL encoding absent", found)
		}
		for _, name := range []string{"x\u2400y", "\u2400"} {
			data, err := volume.ReadFile(name)
			if err != nil || string(data) != "payload" {
				t.Fatal(name, string(data), err)
			}
		}
	}
}
