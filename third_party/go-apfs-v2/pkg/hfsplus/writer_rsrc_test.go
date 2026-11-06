package hfsplus

import (
	"bytes"
	"testing"
)

// TestWriteResourceFork round-trips resource forks through the writer and back
// through this package's reader. A resource fork is a fork of the catalog
// record on HFS+, not an attributes-file record, so it is carried even though
// this writer emits no attributes file.
func TestWriteResourceFork(t *testing.T) {
	small := []byte("a short resource fork\n")
	// Larger than one allocation block, so the fork spans several and the
	// extent arithmetic is exercised rather than just the single-block case.
	large := bytes.Repeat([]byte("resource fork payload. "), 1000)

	root := &Entry{Children: []*Entry{
		{Name: "plain.txt", Mode: 0o644, Data: []byte("no resource fork\n")},
		{Name: "small.txt", Mode: 0o644, Data: []byte("has a small one\n"), ResourceFork: small},
		{Name: "large.txt", Mode: 0o644, Data: []byte("has a large one\n"), ResourceFork: large},
		// A resource fork with no data fork at all is legal.
		{Name: "rsrconly.txt", Mode: 0o644, ResourceFork: small},
	}}

	w := &memWriterAt{}
	if err := CreateImage(w, 0, "RSRC", root, nil); err != nil {
		t.Fatalf("CreateImage: %v", err)
	}

	v, err := New(bytes.NewReader(w.b))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, tc := range []struct {
		name string
		want []byte
	}{
		{"small.txt", small},
		{"large.txt", large},
		{"rsrconly.txt", small},
	} {
		attrs, err := v.Xattrs(tc.name)
		if err != nil {
			t.Errorf("Xattrs(%s): %v", tc.name, err)
			continue
		}
		got, ok := attrs["com.apple.ResourceFork"]
		if !ok {
			t.Errorf("%s: no resource fork was written", tc.name)
			continue
		}
		if !bytes.Equal(got, tc.want) {
			t.Errorf("%s: resource fork is %d bytes, want %d", tc.name, len(got), len(tc.want))
		}
	}

	// A file without one must not acquire an empty fork: fsck_hfs expects the
	// fork descriptor to be all zero, not a zero-length extent.
	attrs, err := v.Xattrs("plain.txt")
	if err != nil {
		t.Fatalf("Xattrs(plain.txt): %v", err)
	}
	if _, ok := attrs["com.apple.ResourceFork"]; ok {
		t.Error("a file with no resource fork reported one")
	}

	// The data forks must be undisturbed by the resource forks sharing the
	// data region.
	if got, err := v.ReadFile("large.txt"); err != nil || string(got) != "has a large one\n" {
		t.Errorf("large.txt data fork = %q, err=%v", got, err)
	}
	if got, err := v.ReadFile("plain.txt"); err != nil || string(got) != "no resource fork\n" {
		t.Errorf("plain.txt data fork = %q, err=%v", got, err)
	}
}

// TestWriteResourceForkDeterministic checks that carrying resource forks does
// not cost the writer its byte-for-byte reproducibility.
func TestWriteResourceForkDeterministic(t *testing.T) {
	build := func() []byte {
		root := &Entry{Children: []*Entry{
			{Name: "a.txt", Mode: 0o644, Data: []byte("a\n"), ResourceFork: []byte("fork a")},
			{Name: "b.txt", Mode: 0o644, Data: []byte("b\n"), ResourceFork: []byte("fork b")},
		}}
		w := &memWriterAt{}
		if err := CreateImage(w, 0, "DET", root, nil); err != nil {
			t.Fatalf("CreateImage: %v", err)
		}
		return w.b
	}
	if !bytes.Equal(build(), build()) {
		t.Error("two runs over the same input produced different images")
	}
}
