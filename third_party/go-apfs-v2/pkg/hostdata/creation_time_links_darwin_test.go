package hostdata

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestCarrierCreationTimeDirectoriesAndLinks(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.Mkdir("directory", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "target"), []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("target", "link"); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("missing", "dangling"); err != nil {
		t.Fatal(err)
	}
	before, err := root.Stat("target")
	if err != nil {
		t.Fatal(err)
	}
	when := time.Unix(978307200, 234567891)
	for _, name := range []string{"directory", "link", "dangling"} {
		file, err := OpenMetadataFile(root, name)
		if err != nil {
			t.Fatal(err)
		}
		if err := SetCreationTime(file, when); err != nil {
			file.Close()
			t.Fatalf("%s: %v", name, err)
		}
		info, err := file.Stat()
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		birth := info.Sys().(*syscall.Stat_t).Birthtimespec
		if birth.Sec != when.Unix() || birth.Nsec != int64(when.Nanosecond()) {
			t.Fatalf("%s birth %v", name, birth)
		}
	}
	after, err := root.Stat("target")
	if err != nil {
		t.Fatal(err)
	}
	if *before.Sys().(*syscall.Stat_t) != *after.Sys().(*syscall.Stat_t) {
		t.Fatal("symlink target modified")
	}
	if _, err := root.Stat("missing"); !os.IsNotExist(err) {
		t.Fatal("dangling target created")
	}
}
