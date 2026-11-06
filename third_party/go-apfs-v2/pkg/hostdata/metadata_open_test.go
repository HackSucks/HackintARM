//go:build darwin || linux || windows

package hostdata

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenMetadataFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file"), []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "dir"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("file", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", filepath.Join(dir, "dangling")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, name := range []string{".", "file", "dir", "link", "dangling"} {
		t.Run(name, func(t *testing.T) {
			file, err := OpenMetadataFile(root, name)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			got, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			want, err := root.Lstat(name)
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(got, want) || got.Mode().Type() != want.Mode().Type() {
				t.Fatal(got, want)
			}
		})
		file, err := OpenMetadataFileRead(root, name)
		if err != nil {
			t.Fatal(err)
		}
		if err = file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"", "../escape", filepath.Join(dir, "file")} {
		if _, err := OpenMetadataFile(root, name); !errors.Is(err, os.ErrInvalid) {
			t.Fatal(name, err)
		}
	}
	if _, err := OpenMetadataFile(nil, "file"); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := OpenMetadataFile(root, "missing"); err == nil {
		t.Fatal("missing accepted")
	}
	if err = root.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenMetadataFile(root, "file"); err == nil {
		t.Fatal("closed root accepted")
	}
}

func TestMetadataOpenFailures(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "other"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, kind := range []string{"open", "stat", "identity"} {
		_, err := openMetadataChecked(root, "file", func(root *os.Root, _ string, _ os.FileInfo) (*os.File, error) {
			if kind == "open" {
				return nil, io.ErrUnexpectedEOF
			}
			f, err := root.Open("other")
			if err != nil {
				t.Fatal(err)
			}
			if kind == "stat" {
				_ = f.Close()
			}
			return f, nil
		})
		if err == nil {
			t.Fatal(kind)
		}
		if kind == "identity" && !errors.Is(err, ErrMetadataIdentity) {
			t.Fatal(err)
		}
	}
	for _, result := range []bool{false, true} {
		f, err := metadataParent(root, "file", func(parent *os.File, _ string) (*os.File, error) {
			if err := parent.Close(); err != nil {
				t.Fatal(err)
			}
			if result {
				return root.Open("file")
			}
			return nil, nil
		})
		if f != nil || err == nil {
			t.Fatal(f, err)
		}
	}
	if err = root.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := metadataParent(root, "file", nil); err == nil {
		t.Fatal("closed parent accepted")
	}
}
