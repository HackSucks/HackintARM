//go:build !darwin

package hostdata

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestAppleDoublePathPortableIO(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("target bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	for name, destination := range map[string]string{"file": target, "dangling": "missing", "outside": outside, "directory": dir} {
		t.Run(name, func(t *testing.T) {
			link := filepath.Join(dir, "link-"+name)
			if err := os.Symlink(destination, link); err != nil {
				t.Fatal(err)
			}
			file, err := openPathPayload(link, os.O_RDONLY, 0600, true, false, 0)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.Lstat(link)
			if err != nil || !os.SameFile(actual, want) || actual.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("link identity was not retained: %v", err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			for _, flags := range []int{os.O_WRONLY, os.O_RDWR, os.O_RDONLY | os.O_TRUNC} {
				file, err := openPathPayload(link, flags, 0600, true, false, 0)
				if err != nil {
					t.Fatal(err)
				}
				if n, err := file.Write([]byte("must not reach target")); n != 0 || err == nil {
					t.Fatal(n, err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := pathUnlink(link); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(link); !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
		})
	}
	file, err := openPathPayload(target, os.O_RDONLY, 0600, true, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(file)
	if err = errors.Join(err, file.Close()); err != nil || string(data) != "target bytes" {
		t.Fatalf("target changed: %q %v", data, err)
	}
	if err := pathSingleWriter(nil); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal(err)
	}
	if err := pathUnlink(dir); !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	if _, err := openPathPayload(filepath.Join(dir, "missing"), os.O_RDONLY, 0600, true, false, 0); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := pathUnlink(target); err != nil {
		t.Fatal(err)
	}
	if err := pathUnlink(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestAppleDoublePathLinkAcquisitionFailures(t *testing.T) {
	marker := errors.New("parent acquisition or close refused")
	for _, fault := range []string{"root", "file", "close-file", "close-no-file"} {
		t.Run(fault, func(t *testing.T) {
			dir := t.TempDir()
			name := filepath.Join(dir, "file")
			if err := os.WriteFile(name, nil, 0600); err != nil {
				t.Fatal(err)
			}
			access := pathLinkAccess{os.OpenRoot, OpenMetadataFileRead, (*os.Root).Close}
			var opened *os.File
			if fault == "root" {
				access.root = func(string) (*os.Root, error) { return nil, marker }
			}
			if fault == "file" || fault == "close-no-file" {
				access.file = func(*os.Root, string) (*os.File, error) { return nil, os.ErrPermission }
			} else {
				access.file = func(root *os.Root, name string) (*os.File, error) {
					var err error
					opened, err = OpenMetadataFileRead(root, name)
					return opened, err
				}
			}
			if fault == "close-file" || fault == "close-no-file" {
				access.close = func(root *os.Root) error { return errors.Join(root.Close(), marker) }
			}
			file, err := openPathLink(name, access)
			if file != nil || err == nil {
				t.Fatalf("partial handle escaped: %v %v", file, err)
			}
			if fault != "file" && !errors.Is(err, marker) {
				t.Fatal(err)
			}
			if (fault == "file" || fault == "close-no-file") && !errors.Is(err, os.ErrPermission) {
				t.Fatal(err)
			}
			if opened != nil {
				if _, err := opened.Read(make([]byte, 1)); !errors.Is(err, os.ErrClosed) {
					t.Fatalf("handle not closed: %v", err)
				}
			}
		})
	}
}
