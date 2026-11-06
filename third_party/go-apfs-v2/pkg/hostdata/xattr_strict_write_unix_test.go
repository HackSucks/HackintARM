//go:build darwin || linux

package hostdata

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func strictWriteNativeRead(t *testing.T, path, name string, want []byte) {
	t.Helper()
	buf := make([]byte, max(len(want)+1, 1))
	n, err := unix.Lgetxattr(path, name, buf)
	if err != nil || n != len(want) || !bytes.Equal(buf[:max(n, 0)], want) {
		t.Fatalf("%s/%s: n=%d value=%x error=%v want=%x", path, name, n, buf, err, want)
	}
}

func TestStrictXattrWriteUnix(t *testing.T) {
	for _, kind := range []string{"file", "directory"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input")
			if kind == "file" {
				if err := os.WriteFile(path, []byte("payload"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			strictSetXattr(t, path, "user.keep", []byte("keep"))
			for _, value := range [][]byte{nil, {0, 1, 255}, {}, bytes.Repeat([]byte{42}, 1024), {7}, nil} {
				before := bytes.Clone(value)
				if err := SetXattr(f, "user.write", value); err != nil {
					t.Fatal(err)
				}
				strictWriteNativeRead(t, path, "user.write", value)
				if !bytes.Equal(value, before) {
					t.Fatal("input changed")
				}
			}
			moved := path + "-moved"
			if err := os.Rename(path, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("decoy"), 0600); err != nil {
				t.Fatal(err)
			}
			strictSetXattr(t, path, "user.write", []byte("decoy"))
			if err := SetXattr(f, "user.write", []byte("held")); err != nil {
				t.Fatal(err)
			}
			strictWriteNativeRead(t, moved, "user.write", []byte("held"))
			strictWriteNativeRead(t, path, "user.write", []byte("decoy"))
			strictWriteNativeRead(t, moved, "user.keep", []byte("keep"))
			if kind == "file" {
				alias := path + "-alias"
				if err := os.Link(moved, alias); err != nil {
					t.Fatal(err)
				}
				if err := SetXattr(f, "user.write", []byte("alias")); err != nil {
					t.Fatal(err)
				}
				strictWriteNativeRead(t, alias, "user.write", []byte("alias"))
				if b, err := io.ReadAll(f); err != nil || string(b) != "payload" {
					t.Fatal("contents/offset", b, err)
				}
			}
		})
	}
	if err := setVisibleXattrFD(-1, "user.write", nil); !errors.Is(err, unix.EBADF) {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	native := unix.Fsetxattr(int(r.Fd()), "user.write", nil, 0)
	if err := SetXattr(r, "user.write", nil); !errors.Is(err, native) {
		t.Fatal("pipe native disagreement", err, native)
	}
}
