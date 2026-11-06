package hostdata

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
)

func TestEntryTypeWindowsRights(t *testing.T) {
	for name, mask := range map[string]uint32{"acl": windows.READ_CONTROL, "ea": windows.FILE_READ_EA, "data": windows.FILE_READ_DATA} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "file")
			if err := os.WriteFile(path, []byte("unchanged"), 0600); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			contentOpenWindowsDeny(t, path, mask)
			if f, err := os.Open(path); err == nil {
				f.Close()
				t.Fatal("generic-read denial ineffective")
			} else if !errors.Is(err, os.ErrPermission) {
				t.Fatal(err)
			}
			if got, err := ReadEntryType(root, "file"); err != nil || got != 0 {
				t.Fatal("query requested unrelated rights", got, err)
			}
		})
	}
}

func TestEntryTypeWindowsClosure(t *testing.T) {
	if _, err := entryTypeFromFile(nil); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	file, err := os.CreateTemp(t.TempDir(), "file")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entryTypeFromFile(file); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("successful query leaked handle", err)
	}
	if _, err := entryTypeFromFile(file); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}
