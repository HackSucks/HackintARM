package hostdata

import (
	"errors"
	"os"

	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func TestStrictXattrWriteDarwin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(path, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(link, unix.O_RDONLY|unix.O_SYMLINK, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), link)
	defer f.Close()
	moved := link + "-moved"
	if err := os.Rename(link, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	strictSetXattr(t, link, "user.write", []byte("decoy"))
	strictSetXattr(t, path, "user.write", []byte("target"))
	if err := SetXattr(f, "user.write", []byte("held")); err != nil {
		t.Fatal(err)
	}
	strictWriteNativeRead(t, moved, "user.write", []byte("held"))
	strictWriteNativeRead(t, link, "user.write", []byte("decoy"))
	strictWriteNativeRead(t, path, "user.write", []byte("target"))
	followed, err := os.Open(link)
	if err != nil {
		t.Fatal(err)
	}
	defer followed.Close()
	if err := SetXattr(followed, "user.write", nil); err != nil {
		t.Fatal(err)
	}
	strictWriteNativeRead(t, path, "user.write", nil)
	if out, err := cirunner.Command("/bin/chmod", "+a", "everyone deny writeextattr", path).CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	defer cirunner.Command("/bin/chmod", "-N", path).Run()
	if err := SetXattr(followed, "user.write", []byte("reject")); !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPERM) {
		t.Fatal("permission denial lost", err)
	}
	strictWriteNativeRead(t, path, "user.write", nil)
}
