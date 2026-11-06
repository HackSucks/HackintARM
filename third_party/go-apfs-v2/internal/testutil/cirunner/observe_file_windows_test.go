package cirunner

import (
	"golang.org/x/sys/windows"
	"os"
	"testing"
)

// Fault fixtures explicitly permit renaming a held file on Windows. Standard
// os.Create disallows this before the observer is involved.
func createMovableFile(t *testing.T, name string) *os.File {
	t.Helper()
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(h), name)
	t.Cleanup(func() { _ = f.Close() })
	return f
}
