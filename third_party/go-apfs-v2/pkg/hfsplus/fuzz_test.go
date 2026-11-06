package hfsplus

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"testing"
	"time"
)

// fuzzSeedImage builds a small HFS+ volume holding a file, a symlink, an
// extended attribute, a Unicode name and nested directories, so the catalog,
// extents and attributes trees all carry records for the fuzzer to mutate.
func fuzzSeedImage(t testing.TB) []byte {
	t.Helper()
	root := &Entry{Children: []*Entry{
		{Name: "hello.txt", Mode: 0o644, Data: []byte("hello world\n"),
			Xattrs: map[string][]byte{"com.example.tag": []byte("v")}},
		{Name: "link", Mode: os.ModeSymlink | 0o755, Data: []byte("hello.txt")},
		{Name: "café", Mode: 0o644, Data: []byte("unicode name\n")},
		{Name: "sub", Mode: os.ModeDir | 0o755, Children: []*Entry{
			{Name: "deep", Mode: os.ModeDir | 0o755, Children: []*Entry{
				{Name: "leaf.txt", Mode: 0o644, Data: []byte("leaf\n")},
			}},
		}},
	}}
	w := &memWriterAt{}
	opts := &CreateOptions{FixedTime: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)}
	if err := CreateImage(w, 0, "Fuzz", root, opts); err != nil {
		t.Fatalf("CreateImage: %v", err)
	}
	return w.b
}

// FuzzVolume opens an HFS+ volume (volume header, extents, catalog and
// attributes B-trees) and walks it, reading every file, link and attribute
// set. It checks only that parsing returns: no panic, no hang, no runaway
// allocation. Run it with, for example,
//
//	go test ./pkg/hfsplus -run '^$' -fuzz '^FuzzVolume$' -fuzztime 30s -fuzzminimizetime 1s
func FuzzVolume(f *testing.F) {
	f.Add(fuzzSeedImage(f))
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := New(bytes.NewReader(data))
		if err != nil {
			return
		}
		visited := 0
		_ = fs.WalkDir(v, ".", func(name string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if visited++; visited > 1000 {
				return fs.SkipAll
			}
			_, _ = v.Xattrs(name)
			switch {
			case d.Type()&fs.ModeSymlink != 0:
				_, _ = v.Readlink(name)
			case d.Type().IsRegular():
				if file, err := v.Open(name); err == nil {
					_, _ = io.CopyN(io.Discard, file, 1<<20)
					file.Close()
				}
			}
			return nil
		})
	})
}
