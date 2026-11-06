package hostdata

import (
	"encoding/json"
	"errors"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/entrytype"
	"os"

	"path/filepath"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func TestEntryTypeNative(t *testing.T) {
	type result struct {
		Errno     int
		Vnode     uint32 `json:"vnode_type"`
		Size      uint32
		StatErrno int `json:"stat_errno"`
	}
	var corpus struct{ Cases map[string]result }
	data, err := os.ReadFile("../../testdata/appledouble/native/entry-type.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) != len(entrytype.Cases) {
		t.Fatal("incomplete corpus")
	}
	dir, err := os.MkdirTemp("/tmp", "entry-type-live-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	oracle := filepath.Join(dir, "oracle")
	metadataStatCommand(t, "/usr/bin/clang", "-Wall", "-Wextra", "-Werror", "../../testdata/appledouble/native/entry-type.c", "-o", oracle)
	for _, name := range entrytype.Cases {
		t.Run(name, func(t *testing.T) {
			parent := filepath.Join(dir, name)
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal(err)
			}
			cleanup, err := entrytype.Make(parent, name)
			defer func() {
				if err := cleanup(); err != nil {
					t.Error(err)
				}
			}()
			if err != nil {
				t.Fatal(err)
			}
			b, err := cirunner.Command(oracle, parent).Output()
			if err != nil {
				t.Fatal(err)
			}
			var native result
			if err := json.Unmarshal(b, &native); err != nil {
				t.Fatal(err)
			}
			if native != corpus.Cases[name] {
				t.Fatal("native reference changed", native, corpus.Cases[name])
			}
			root, err := os.OpenRoot(parent)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			got, err := ReadEntryType(root, "file")
			code := entryTypeErrno(t, err)
			if code != native.Errno {
				t.Fatal("Go/native errno", code, native)
			}
			if code == 0 {
				want := map[uint32]os.FileMode{1: 0, 2: os.ModeDir, 5: os.ModeSymlink, 6: os.ModeSocket, 7: os.ModeNamedPipe}[native.Vnode]
				if got != want || native.Size != 8 {
					t.Fatal("Go/native type", got, native)
				}
			}
			_, err = StatMetadata(root, "file")
			if code := entryTypeErrno(t, err); code != native.StatErrno {
				t.Fatal("stat control differs", code, native)
			}
		})
	}
}
func entryTypeErrno(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		t.Fatal(err)
	}
	return int(errno)
}
