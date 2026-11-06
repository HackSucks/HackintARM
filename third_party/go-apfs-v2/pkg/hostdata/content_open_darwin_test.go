package hostdata

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"

	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func TestContentOpenNative(t *testing.T) {
	type result struct {
		Errno     int
		WrongType bool `json:"wrong_type"`
		Hex       string
	}
	var corpus struct{ Cases map[string]result }
	data, err := os.ReadFile("../../testdata/appledouble/native/content-open.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) != 12 {
		t.Fatal("incomplete native corpus")
	}
	oracle := filepath.Join(t.TempDir(), "oracle")
	metadataStatCommand(t, "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "../../testdata/appledouble/native/content-open.c", "-o", oracle)
	for name, want := range corpus.Cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "file")
			switch name {
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.WriteFile(filepath.Join(dir, "target"), []byte("unchanged"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("target", path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
			default:
				if err := os.WriteFile(path, []byte("unchanged"), 0600); err != nil {
					t.Fatal(err)
				}
				if name != "ordinary" {
					metadataStatCommand(t, "/bin/chmod", "+a", "everyone deny "+name, path)
					t.Cleanup(func() { metadataStatCommand(t, "/bin/chmod", "-N", path) })
				}
			}
			b, err := cirunner.Command(oracle, dir, "file").Output()
			if err != nil {
				t.Fatal(err)
			}
			var native result
			if err := json.Unmarshal(b, &native); err != nil {
				t.Fatal(err)
			}
			if native != want {
				t.Fatal("native behavior changed", native, want)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			var got result
			f, err := OpenContentFileRead(root, "file")
			if err == nil {
				data, readErr := io.ReadAll(f)
				err = errors.Join(readErr, f.Close())
				got.Hex = hex.EncodeToString(data)
			}
			if errors.Is(err, ErrContentType) {
				got.WrongType = true
			} else if err != nil {
				var errno syscall.Errno
				if !errors.As(err, &errno) {
					t.Fatal(err)
				}
				got.Errno = int(errno)
			}
			if !reflect.DeepEqual(got, native) {
				t.Fatalf("Go %+v; C %+v", got, native)
			}
			if name == "readsecurity" {
				if _, err := StatMetadata(root, "file"); !errors.Is(err, os.ErrPermission) {
					t.Fatal("ACL-read denial ineffective", err)
				}
			}
			if name == "readextattr" {
				f, err := OpenContentFileRead(root, "file")
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				if _, _, err := ReadXattr(f, "user.content-control", 128); !errors.Is(err, os.ErrPermission) {
					t.Fatal("EA-read denial ineffective", err)
				}
			}
		})
	}
}
