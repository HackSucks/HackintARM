package hostdata

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestStrictXattrLinuxPathDescriptor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, []byte("contents"), 0600); err != nil {
		t.Fatal(err)
	}
	strictSetXattr(t, path, "user.strict", []byte("keep"))
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	if _, present, err := XattrSize(file, "user.strict"); present || !errors.Is(err, unix.EBADF) {
		t.Fatal(present, err)
	}
	if data, present, err := ReadXattr(file, "user.strict", 4); data != nil || present || !errors.Is(err, unix.EBADF) {
		t.Fatal(data, present, err)
	}
	if names, err := ListXattrNames(file, MaxXattrListSize); names != nil || !errors.Is(err, unix.EBADF) {
		t.Fatal(names, err)
	}
	if err := SetXattr(file, "user.strict", []byte("reject")); !errors.Is(err, unix.EBADF) {
		t.Fatal(err)
	}
	if removed, err := RemoveXattr(file, "user.strict"); removed || !errors.Is(err, unix.EBADF) {
		t.Fatal(removed, err)
	}
	if data, present, err := ReadXattrNoFollow(path, "user.strict", 4); string(data) != "keep" || !present || err != nil {
		t.Fatal(data, present, err)
	}
}

func TestStrictXattrLinuxPermissionErrors(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-denial assertion requires an unprivileged user")
	}
	path := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(path, []byte("contents"), 0600); err != nil {
		t.Fatal(err)
	}
	strictSetXattr(t, path, "user.strict", []byte("keep"))
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0600) })
	for _, operation := range []func() error{
		func() error { return SetXattr(file, "user.strict", []byte("reject")) },
		func() error { _, _, err := XattrSize(file, "user.strict"); return err },
		func() error { _, _, err := ReadXattr(file, "user.strict", 4); return err },
		func() error { _, _, err := XattrSizeNoFollow(path, "user.strict"); return err },
		func() error { _, _, err := ReadXattrNoFollow(path, "user.strict", 4); return err },
		func() error { _, err := RemoveXattr(file, "user.strict"); return err },
		func() error { _, err := RemoveXattrNoFollow(path, "user.strict"); return err },
	} {
		if err := operation(); !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPERM) {
			t.Fatal("permission error suppressed", err)
		}
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if got, present, err := ReadXattr(file, "user.strict", 4); string(got) != "keep" || !present || err != nil {
		t.Fatal(got, present, err)
	}
}
