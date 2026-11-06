//go:build darwin || linux

package hostdata

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

func strictSetXattr(t *testing.T, path, name string, value []byte) {
	t.Helper()
	if err := unix.Lsetxattr(path, name, value, 0); err != nil {
		t.Fatalf("fixture xattr %s on %s: %v", name, path, err)
	}
}

func TestStrictXattrHostLifecycle(t *testing.T) {
	// ext4 may store names, values and metadata in one 4 KiB block. A 4 KiB
	// value alone is not a portable fixture (ENOSPC even on an empty volume).
	lengths := []int{0, 1, 1024}
	if runtime.GOOS == "darwin" {
		lengths = append(lengths, 4096)
	}
	for _, kind := range []string{"file", "directory"} {
		for _, length := range lengths {
			t.Run(fmt.Sprintf("%s/%d", kind, length), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "input")
				if kind == "directory" {
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(path, []byte("contents"), 0600); err != nil {
					t.Fatal(err)
				}
				file, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				name := "user.strict"
				want := bytes.Repeat([]byte("x"), length)
				for _, byPath := range []bool{false, true} {
					t.Run(fmt.Sprintf("path-%t", byPath), func(t *testing.T) {
						size := func() (int, bool, error) {
							if byPath {
								return XattrSizeNoFollow(path, name)
							}
							return XattrSize(file, name)
						}
						read := func(limit int) ([]byte, bool, error) {
							if byPath {
								return ReadXattrNoFollow(path, name, limit)
							}
							return ReadXattr(file, name, limit)
						}
						remove := func() (bool, error) {
							if byPath {
								return RemoveXattrNoFollow(path, name)
							}
							return RemoveXattr(file, name)
						}
						if n, present, err := size(); n != 0 || present || err != nil {
							t.Fatal(n, present, err)
						}
						if b, present, err := read(length); b != nil || present || err != nil {
							t.Fatal(b, present, err)
						}
						strictSetXattr(t, path, name, want)
						strictSetXattr(t, path, "user.unrelated", []byte("keep"))
						if n, present, err := size(); n != length || !present || err != nil {
							t.Fatal(n, present, err)
						}
						if b, present, err := read(length); b == nil || !bytes.Equal(b, want) || !present || err != nil {
							t.Fatal(b, present, err)
						}
						if length > 0 {
							if b, present, err := read(length - 1); b != nil || present || !errors.Is(err, ErrXattrTooLarge) {
								t.Fatal(b, present, err)
							}
						}
						if removed, err := remove(); !removed || err != nil {
							t.Fatal(removed, err)
						}
						if removed, err := remove(); removed || err != nil {
							t.Fatal(removed, err)
						}
						if n, err := unix.Lgetxattr(path, name, nil); !missingXattr(err) {
							t.Fatal("native removal", n, err)
						}
						buf := make([]byte, 4)
						if n, err := unix.Lgetxattr(path, "user.unrelated", buf); err != nil || n != 4 || string(buf) != "keep" {
							t.Fatal("unrelated", n, buf, err)
						}
					})
				}
				if kind == "file" {
					b, err := io.ReadAll(file)
					if err != nil || string(b) != "contents" {
						t.Fatal("contents or position changed", string(b), err)
					}
				}
			})
		}
	}
}

func TestStrictXattrHeldIdentity(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "original")
	moved := filepath.Join(dir, "moved")
	alias := filepath.Join(dir, "alias")
	if err := os.WriteFile(original, []byte("original bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	strictSetXattr(t, original, "user.strict", []byte("held"))
	file, err := os.Open(original)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Seek(3, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(original, alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(original, []byte("decoy bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	strictSetXattr(t, original, "user.strict", []byte("decoy"))
	if n, present, err := XattrSize(file, "user.strict"); n != 4 || !present || err != nil {
		t.Fatal(n, present, err)
	}
	if b, present, err := ReadXattr(file, "user.strict", 4); string(b) != "held" || !present || err != nil {
		t.Fatal(string(b), present, err)
	}
	if removed, err := RemoveXattr(file, "user.strict"); !removed || err != nil {
		t.Fatal(removed, err)
	}
	for _, path := range []string{moved, alias} {
		if _, present, err := XattrSizeNoFollow(path, "user.strict"); present || err != nil {
			t.Fatal(path, present, err)
		}
	}
	if b, present, err := ReadXattrNoFollow(original, "user.strict", 5); string(b) != "decoy" || !present || err != nil {
		t.Fatal(string(b), present, err)
	}
	if pos, err := file.Seek(0, io.SeekCurrent); pos != 3 || err != nil {
		t.Fatal(pos, err)
	}
	if b, err := os.ReadFile(moved); string(b) != "original bytes" || err != nil {
		t.Fatal(string(b), err)
	}
}

func TestStrictXattrNoFollow(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("content"), 0600); err != nil {
		t.Fatal(err)
	}
	strictSetXattr(t, target, "user.strict", []byte("target"))
	if err := os.Symlink("target", link); err != nil {
		t.Fatal(err)
	}
	if _, present, err := XattrSizeNoFollow(link, "user.strict"); present || err != nil {
		t.Fatal(present, err)
	}
	if b, present, err := ReadXattrNoFollow(link, "user.strict", 6); b != nil || present || err != nil {
		t.Fatal(b, present, err)
	}
	if removed, err := RemoveXattrNoFollow(link, "user.strict"); removed || err != nil && !errors.Is(err, unix.EPERM) {
		t.Fatal(removed, err)
	}
	if b, present, err := ReadXattrNoFollow(target, "user.strict", 6); string(b) != "target" || !present || err != nil {
		t.Fatal(string(b), present, err)
	}
	file, err := os.Open(link)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if b, present, err := ReadXattr(file, "user.strict", 6); string(b) != "target" || !present || err != nil {
		t.Fatal(string(b), present, err)
	}
	if runtime.GOOS == "darwin" {
		strictSetXattr(t, link, "user.strict", []byte("link"))
		if b, present, err := ReadXattrNoFollow(link, "user.strict", 4); string(b) != "link" || !present || err != nil {
			t.Fatal(string(b), present, err)
		}
		if removed, err := RemoveXattrNoFollow(link, "user.strict"); !removed || err != nil {
			t.Fatal(removed, err)
		}
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if _, present, err := XattrSizeNoFollow(link, "user.strict"); present || err != nil {
		t.Fatal("dangling link", present, err)
	}
}

func TestStrictXattrNativeErrors(t *testing.T) {
	missing := missingXattrError
	if n, present, err := visibleXattrSize(func([]byte) (int, error) { return -1, missing }); n != 0 || present || err != nil {
		t.Fatal(n, present, err)
	}
	if removed, err := removeVisibleXattr(func() error { return missing }); removed || err != nil {
		t.Fatal(removed, err)
	}
	for _, second := range []error{missing, unix.ERANGE, unix.EIO, unix.EPERM, unix.ENOTSUP} {
		calls := 0
		b, present, err := readVisibleXattr(func([]byte) (int, error) {
			calls++
			if calls == 1 {
				return 4, nil
			}
			return -1, second
		}, 4)
		if b != nil || present || !errors.Is(err, second) {
			t.Fatal(b, present, err)
		}
		if errors.Is(err, ErrXattrChanged) != (second == missing || second == unix.ERANGE) {
			t.Fatal(err)
		}
	}
	for _, cause := range []error{unix.ENOTSUP, unix.EOPNOTSUPP, unix.ENOSYS} {
		err := strictXattrError(cause)
		if !errors.Is(err, ErrXattrUnsupported) || !errors.Is(err, cause) {
			t.Fatal(err)
		}
	}
	for _, cause := range []error{unix.EPERM, unix.EACCES, unix.EIO, unix.ENOENT} {
		if err := strictXattrError(cause); !errors.Is(err, cause) || errors.Is(err, ErrXattrUnsupported) {
			t.Fatal(err)
		}
	}
}
