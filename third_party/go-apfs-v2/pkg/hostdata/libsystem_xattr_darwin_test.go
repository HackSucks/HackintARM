package hostdata

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestLibSystemXattrNative(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	const name = "user.libsystem"
	if err := unix.Fsetxattr(int(f.Fd()), name, []byte("original"), 0); err != nil {
		t.Fatal(err)
	}
	value, err := getXattr(file, name)
	if err != nil || string(value) != "original" {
		t.Fatalf("%q %v", value, err)
	}
	names, err := listXattrNames(file)
	if err != nil || len(names) == 0 {
		t.Fatalf("%v %v", names, err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := getXattr(link, name); !errors.Is(err, unix.ENOATTR) {
		t.Fatalf("followed symlink: %v", err)
	}
	if err := unix.Fsetxattr(int(f.Fd()), name, []byte{}, 0); err != nil {
		t.Fatal(err)
	}
	if value, err := getXattr(file, name); err != nil || value == nil || len(value) != 0 {
		t.Fatalf("empty: %v %v", value, err)
	}
	for _, path := range []string{file + "absent", "bad\x00path"} {
		if _, err := listXattrNames(path); err == nil {
			t.Fatal("missing listing error")
		}
		if _, err := getXattr(path, name); err == nil {
			t.Fatal("missing read error")
		}
	}
	if _, err := getXattr(file, "bad\x00name"); err == nil {
		t.Fatal("missing invalid-name error")
	}
	if _, err := getCaptureXattrFD(int(f.Fd()), "bad\x00name", nil); err == nil {
		t.Fatal("missing invalid-name error")
	}
	// Position and options ABI: hidden compression metadata must be seen by the
	// capture path without changing ordinary visibility. Type 1 is inline data.
	compression := []byte{0x66, 0x70, 0x6d, 0x63, 1, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 'a', 'b', 'c'}
	if err := unix.Fsetxattr(int(f.Fd()), DecmpfsName, compression, 0); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fchflags(int(f.Fd()), unix.UF_COMPRESSED); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Fgetxattr(int(f.Fd()), DecmpfsName, nil); !errors.Is(err, unix.ENOATTR) {
		t.Fatalf("storage attribute should be hidden: %v", err)
	}
	values, err := CaptureXattrs(context.Background(), f, XattrCaptureLimits{1 << 20, 1 << 20, 2 << 20})
	if err != nil || !bytes.Equal(values[DecmpfsName], compression) {
		t.Fatalf("hidden capture: %v %v", values, err)
	}
	if err := os.Rename(file, file+"renamed"); err != nil {
		t.Fatal(err)
	}
	values, err = CaptureXattrs(context.Background(), f, XattrCaptureLimits{1 << 20, 1 << 20, 2 << 20})
	if err != nil || !bytes.Equal(values[DecmpfsName], compression) {
		t.Fatalf("held capture: %v %v", values, err)
	}
}

func TestLibSystemBindingFailures(t *testing.T) {
	fault := errors.New("symbol not found")
	old := loadDarwinXattr
	loadDarwinXattr = func() (*darwinXattrABI, error) { return nil, fault }
	defer func() { loadDarwinXattr = old }()
	if _, err := darwinListXattrPath("file", nil, 0); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	if _, err := darwinGetXattrPath("file", "name", nil, 0); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	if _, err := listCaptureXattrFD(1, 100); !errors.Is(err, fault) {
		t.Fatal(err)
	}
	if _, err := getCaptureXattrFD(1, "name", nil); !errors.Is(err, fault) {
		t.Fatal(err)
	}
}

// The controlled ABI path must carry the same positions, sizes, visibility
// options and errno as the native symbol path. It supports deterministic native
// boundary failures without delegating policy to C.
func TestLibSystemXattrFallbackABI(t *testing.T) {
	const name = "user.fallback"
	errno := int32(syscall.EACCES)
	fail := false
	copyResult := func(buf *byte, size uintptr, data []byte) (int64, error) {
		if fail {
			return -1, syscall.Errno(errno)
		}
		if size != 0 {
			if size < uintptr(len(data)) {
				t.Fatal("ABI buffer smaller than requested data")
			}
			copy(unsafe.Slice(buf, int(size)), data)
		}
		return int64(len(data)), nil
	}
	checkString := func(ptr *byte, want string) {
		if !bytes.Equal(unsafe.Slice(ptr, len(want)+1), append([]byte(want), 0)) {
			t.Fatal("ABI string did not preserve its terminating NUL")
		}
	}
	a := &darwinXattrABI{
		listPath: func(path, buf *byte, size uintptr, flags int32) (int64, error) {
			checkString(path, "fixture")
			if flags != 17 {
				t.Fatal("path options lost", flags)
			}
			return copyResult(buf, size, []byte(name+"\x00"))
		},
		getPath: func(path, attr, buf *byte, size uintptr, position uint32, flags int32) (int64, error) {
			checkString(path, "fixture")
			checkString(attr, name)
			if position != 0 || flags != 17 {
				t.Fatal("path read position/options lost", position, flags)
			}
			return copyResult(buf, size, []byte("ok"))
		},
		listFD: func(fd int32, buf *byte, size uintptr, flags int32) (int64, error) {
			if fd != 19 || flags != xattrShowCompression {
				t.Fatal("held descriptor/hidden visibility lost", fd, flags)
			}
			return copyResult(buf, size, []byte(name+"\x00"))
		},
		getFD: func(fd int32, attr, buf *byte, size uintptr, position uint32, flags int32) (int64, error) {
			checkString(attr, name)
			if fd != 19 || position != 0 || flags != xattrShowCompression {
				t.Fatal("held read descriptor/position/options lost", fd, position, flags)
			}
			return copyResult(buf, size, []byte("ok"))
		},
	}
	old := loadDarwinXattr
	loadDarwinXattr = func() (*darwinXattrABI, error) { return a, nil }
	defer func() { loadDarwinXattr = old }()
	for _, failed := range []bool{false, true} {
		fail = failed
		buf := make([]byte, len(name)+1)
		n, pathList := darwinListXattrPath("fixture", buf, 17)
		value := make([]byte, 2)
		m, pathRead := darwinGetXattrPath("fixture", name, value, 17)
		names, heldList := listCaptureXattrFD(19, 1024)
		heldValue := make([]byte, 2)
		k, heldRead := getCaptureXattrFD(19, name, heldValue)
		for _, err := range []error{pathList, pathRead, heldList, heldRead} {
			if failed && !errors.Is(err, syscall.EACCES) || !failed && err != nil {
				t.Fatal("ABI errno mismatch", failed, err)
			}
		}
		if !failed && (n != len(buf) || m != 2 || k != 2 || string(value) != "ok" || string(heldValue) != "ok" || len(names) != 1 || names[0] != name) {
			t.Fatal("ABI values changed", n, m, k, names)
		}
	}
}
