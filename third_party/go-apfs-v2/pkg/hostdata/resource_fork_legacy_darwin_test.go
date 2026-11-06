package hostdata

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
	"golang.org/x/sys/unix"
)

func TestCompressionResourceForkVersionRouting(t *testing.T) {
	marker := errors.New("open marker")
	for _, major := range []uint32{15, 26, 27} {
		var selected string
		detect := func(ctx context.Context) (osversion.Version, error) {
			if ctx == nil {
				t.Fatal("nil context")
			}
			return osversion.Version{Major: major}, nil
		}
		openat := func(fd int, path string, flags int, mode uint32) (int, error) {
			selected = "openat"
			if fd != 123 || path != "..namedfork/rsrc" || flags != 45 || mode != 0600 {
				t.Fatal("arguments")
			}
			return 456, marker
		}
		legacy := func(fd, flags int, mode uint32) (int, error) {
			selected = "legacy"
			if fd != 123 || flags != 45 || mode != 0600 {
				t.Fatal("arguments")
			}
			return 456, marker
		}
		got, err := openResourceForkAtUsing(123, "..namedfork/rsrc", 45, 0600, detect, openat, legacy)
		want := "openat"
		if major == 15 {
			want = "legacy"
		}
		if got != 456 || !errors.Is(err, marker) || selected != want {
			t.Fatal(got, err, selected, want)
		}
	}
	if _, err := openResourceForkAtUsing(0, "other", 0, 0, nil, nil, nil); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := openResourceForkAtUsing(0, "..namedfork/rsrc", 0, 0, func(context.Context) (osversion.Version, error) { return osversion.Version{}, marker }, nil, nil); !errors.Is(err, marker) {
		t.Fatal(err)
	}
	if _, err := openResourceForkAtUsing(0, "..namedfork/rsrc", 0, 0, func(context.Context) (osversion.Version, error) { return osversion.Version{Major: 28}, nil }, nil, nil); !errors.Is(err, osversion.ErrMacOSProfile) {
		t.Fatal(err)
	}
}

func TestCompressionResourceForkLegacyFailures(t *testing.T) {
	marker, cleanup := errors.New("native fault"), errors.New("cleanup fault")
	for _, fault := range []string{"source-stat", "source-kind", "getpath", "open", "fork-stat", "fork-kind", "device", "inode", "truncate", "close", "success"} {
		t.Run(fault, func(t *testing.T) {
			closed, truncated := false, false
			calls := legacyForkCalls{
				stat: func(fd int, s *unix.Stat_t) error {
					*s = unix.Stat_t{Mode: unix.S_IFREG | 0600, Dev: 11, Ino: 22}
					if fd == 123 {
						if fault == "source-stat" {
							return marker
						}
						if fault == "source-kind" {
							s.Mode = unix.S_IFDIR
						}
						return nil
					}
					if fd != 456 {
						t.Fatal("stat unexpected fd", fd)
					}
					switch fault {
					case "fork-stat":
						return marker
					case "fork-kind":
						s.Mode = unix.S_IFDIR
					case "device":
						s.Dev++
					case "inode", "close":
						s.Ino++
					}
					return nil
				},
				path: func(fd int) (string, error) {
					if fd != 123 {
						t.Fatal(fd)
					}
					if fault == "getpath" {
						return "", marker
					}
					return "/current", nil
				},
				open: func(path string, flags int, mode uint32) (int, error) {
					if path != "/current/..namedfork/rsrc" || flags != (unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC) || mode != 0600 {
						t.Fatal("unsafe open arguments", path, flags, mode)
					}
					if fault == "open" {
						return -1, marker
					}
					return 456, nil
				},
				truncate: func(fd int, n int64) error {
					if fd != 456 || n != 0 {
						t.Fatal(fd, n)
					}
					truncated = true
					if fault == "truncate" {
						return marker
					}
					return nil
				},
				close: func(fd int) error {
					if fd != 456 || closed {
						t.Fatal("incorrect cleanup", fd, closed)
					}
					closed = true
					if fault == "close" {
						return cleanup
					}
					return nil
				},
			}
			got, err := openLegacyResourceForkUsing(123, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_TRUNC, 0600, calls)
			if fault == "success" {
				if got != 456 || err != nil || closed || !truncated {
					t.Fatal(got, err, closed, truncated)
				}
				return
			}
			if got != -1 || err == nil {
				t.Fatal("fault ignored", got, err)
			}
			beforeOpen := fault == "source-stat" || fault == "source-kind" || fault == "getpath" || fault == "open"
			if closed == beforeOpen {
				t.Fatal("descriptor ownership", closed, beforeOpen)
			}
			if truncated != (fault == "truncate") {
				t.Fatal("truncation before identity validation", truncated)
			}
			if fault == "close" && (!errors.Is(err, ErrMetadataIdentity) || !errors.Is(err, cleanup)) {
				t.Fatal(err)
			}
		})
	}
	for _, data := range [][]byte{nil, {}, []byte("relative\x00"), []byte("/unterminated"), {0}} {
		if _, err := terminatedHeldPath(data); !errors.Is(err, fs.ErrInvalid) {
			t.Fatal(data, err)
		}
	}
	if _, err := nativeHeldPath(-1); !errors.Is(err, unix.EBADF) {
		t.Fatal(err)
	}
}

// Exercise the older kernel route even on newer macOS. A namespace replacement
// after F_GETPATH must not truncate or overwrite the replacement's resource fork.
func TestCompressionResourceForkLegacyIdentity(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "source")
	file, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err = SetXattr(file, ResourceForkName, []byte("original")); err != nil {
		t.Fatal(err)
	}
	fork, err := openLegacyResourceFork(int(file.Fd()), unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	opened := os.NewFile(uintptr(fork), "older native fork")
	got, err := io.ReadAll(opened)
	if err != nil || !bytes.Equal(got, []byte("original")) {
		t.Fatal(got, err)
	}
	if err = opened.Close(); err != nil {
		t.Fatal(err)
	}
	calls := legacyForkCalls{nativeHeldPath, unix.Fstat, func(path string, flags int, mode uint32) (int, error) {
		if err := os.Rename(name, name+".moved"); err != nil {
			t.Fatal(err)
		}
		shadow, err := os.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if err = SetXattr(shadow, ResourceForkName, []byte("replacement")); err != nil {
			t.Fatal(err)
		}
		if err = shadow.Close(); err != nil {
			t.Fatal(err)
		}
		return unix.Open(path, flags, mode)
	}, unix.Ftruncate, unix.Close}
	if fd, err := openLegacyResourceForkUsing(int(file.Fd()), unix.O_RDWR|unix.O_CREAT|unix.O_TRUNC, 0600, calls); fd != -1 || !errors.Is(err, ErrMetadataIdentity) {
		t.Fatal(fd, err)
	}
	shadow, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer shadow.Close()
	got, present, err := ReadXattr(shadow, ResourceForkName, 32)
	if err != nil || !present || !bytes.Equal(got, []byte("replacement")) {
		t.Fatal("replacement modified", got, err)
	}
	fd, err := openLegacyResourceFork(int(file.Fd()), unix.O_RDWR|unix.O_CREAT|unix.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	got, present, err = ReadXattr(file, ResourceForkName, 32)
	if err != nil || present || len(got) != 0 {
		t.Fatal("original fork not truncated", got, err)
	}
}
