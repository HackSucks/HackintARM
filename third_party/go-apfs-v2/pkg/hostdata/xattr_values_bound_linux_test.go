package hostdata

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCarrierLinuxSymlinkCapture(t *testing.T) {
	rootPath := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("secret target"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(outside, "user.target-only", []byte("must not borrow"), 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, "file"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(filepath.Join(rootPath, "file"), "user.target-only", []byte("inside"), 0); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	limits := XattrCaptureLimits{NameBytes: MaxXattrListSize, ValueBytes: 1024, TotalBytes: 4096}
	for name, target := range map[string]string{"inside": "file", "outside": outside, "dangling": "missing", "directory": "."} {
		if err := os.Symlink(target, filepath.Join(rootPath, name)); err != nil {
			t.Fatal(err)
		}
		expected, err := CaptureXattrsNoFollow(context.Background(), filepath.Join(rootPath, name), limits)
		if err != nil {
			t.Fatal(err)
		}
		values, err := CaptureXattrValuesAt(context.Background(), root, name, limits)
		if err != nil {
			t.Fatal(name, err)
		}
		got := map[string][]byte{}
		for n, v := range values {
			b := make([]byte, v.Size())
			if _, e := v.ReadAt(b, 0); e != nil && !errors.Is(e, io.EOF) {
				t.Fatal(e)
			}
			got[n] = b
		}
		if !reflect.DeepEqual(got, expected) {
			t.Fatal(name, got, expected)
		}
		if _, ok := got["user.target-only"]; ok {
			t.Fatal("followed target", name)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if values, err := CaptureXattrValuesAt(ctx, root, "inside", limits); !errors.Is(err, context.Canceled) || values != nil {
		t.Fatal(values, err)
	}
	limits.NameBytes = -1
	if values, err := CaptureXattrValuesAt(context.Background(), root, "inside", limits); !errors.Is(err, os.ErrInvalid) || values != nil {
		t.Fatal(values, err)
	}
	if values, err := CaptureXattrValuesAt(context.Background(), root, "inside", XattrCaptureLimits{}); err != nil || len(values) != 0 {
		t.Fatal(values, err)
	}
}

func TestCarrierLinuxSymlinkBinding(t *testing.T) {
	for _, scenario := range []string{"preserve", "rename-parent", "replace-before", "replace-after", "remove-after", "capture-error", "parent-closed"} {
		t.Run(scenario, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "parent")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(dir, "link")
			if err := os.Symlink("missing", link); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			originalFile, err := OpenMetadataFileRead(root, "link")
			if err != nil {
				t.Fatal(err)
			}
			defer originalFile.Close()
			original, err := originalFile.Stat()
			if err != nil {
				t.Fatal(err)
			}
			parent, err := root.Open(".")
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			if scenario == "rename-parent" {
				if err := os.Rename(dir, dir+"-moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("replacement", link); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "replace-before" {
				if err := os.Remove(link); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("other", link); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "parent-closed" {
				parent.Close()
			}
			values, err := captureLinkXattrValues(context.Background(), parent, "link", original, XattrCaptureLimits{}, func(ctx context.Context, bound string, _ XattrCaptureLimits) (map[string][]byte, error) {
				target, e := os.Readlink(bound)
				if e != nil || target != "missing" {
					t.Fatal(target, e)
				}
				if scenario == "capture-error" {
					return nil, io.ErrClosedPipe
				}
				if scenario == "replace-after" || scenario == "remove-after" {
					if e := os.Remove(bound); e != nil {
						t.Fatal(e)
					}
				}
				if scenario == "replace-after" {
					if e := os.Symlink("changed", bound); e != nil {
						t.Fatal(e)
					}
				}
				return map[string][]byte{"security.logical": []byte("link-only")}, ctx.Err()
			})
			switch scenario {
			case "preserve", "rename-parent":
				if err != nil || len(values) != 1 {
					t.Fatal(values, err)
				}
				data := make([]byte, values["security.logical"].Size())
				if _, err := values["security.logical"].ReadAt(data, 0); err != nil || string(data) != "link-only" {
					t.Fatal(string(data), err)
				}
			case "replace-before", "replace-after":
				if !errors.Is(err, ErrMetadataIdentity) || values != nil {
					t.Fatal(values, err)
				}
			case "remove-after":
				if !errors.Is(err, os.ErrNotExist) || values != nil {
					t.Fatal(values, err)
				}
			case "capture-error":
				if !errors.Is(err, io.ErrClosedPipe) || values != nil {
					t.Fatal(values, err)
				}
			case "parent-closed":
				conn, expected := parent.SyscallConn()
				if expected == nil {
					expected = conn.Control(func(uintptr) { t.Fatal("closed descriptor remained usable") })
				}
				if expected == nil || !errors.Is(err, expected) || values != nil {
					t.Fatal(values, err)
				}
			}
		})
	}
}

func TestCarrierLinuxBoundCaptureFailures(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink("missing", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	file, err := OpenMetadataFileRead(root, "link")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	root.Close()
	if values, err := captureXattrValuesBound(context.Background(), root, "link", file, XattrCaptureLimits{}); err == nil || values != nil {
		t.Fatal(values, err)
	}
	file.Close()
	if values, err := captureXattrValuesBound(context.Background(), root, "link", file, XattrCaptureLimits{}); err == nil || values != nil {
		t.Fatal(values, err)
	}
}
