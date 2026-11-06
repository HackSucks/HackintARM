//go:build darwin || linux

package hostdata

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEntryTypeUnixObjects(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "entry-type-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := unix.Mkfifo(filepath.Join(dir, "pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: filepath.Join(dir, "socket")}); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for name, want := range map[string]os.FileMode{"pipe": os.ModeNamedPipe, "socket": os.ModeSocket} {
		if got, err := ReadEntryType(root, name); err != nil || got != want {
			t.Fatal(name, got, err)
		}
	}
	device, err := os.OpenRoot("/dev")
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	if got, err := ReadEntryType(device, "null"); err != nil || got != os.ModeDevice|os.ModeCharDevice {
		t.Fatal(got, err)
	}
}

func TestEntryTypeUnixDataDenial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := os.WriteFile(path, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "darwin" {
		metadataStatCommand(t, "/bin/chmod", "+a", "everyone deny read", path)
		t.Cleanup(func() { metadataStatCommand(t, "/bin/chmod", "-N", path) })
	} else {
		if err := os.Chmod(path, 0000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(path, 0600) })
	}
	if f, err := os.Open(path); err == nil {
		f.Close()
		t.Fatal("data denial ineffective")
	} else if !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if got, err := ReadEntryType(root, "file"); err != nil || got != 0 {
		t.Fatal("query required data", got, err)
	}
}
