package cirunner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestObservationOpenErrorsAndHeldRename(t *testing.T) {
	for _, name := range []string{"bad\x00path", filepath.Join(t.TempDir(), "missing")} {
		if f, err := openObservationFile(name); err == nil {
			_ = f.Close()
			t.Fatal("accepted invalid observation source", name)
		}
	}
	path := filepath.Join(t.TempDir(), "raw")
	original := createMovableFile(t, path)
	reader, err := openObservationFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	before, err := original.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path, path+"-held"); err != nil {
		t.Fatal("observer introduced a rename lock", err)
	}
	if err = os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	held, err := reader.Stat()
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, held) || os.SameFile(held, after) {
		t.Fatal("observer lost held identity")
	}
}
