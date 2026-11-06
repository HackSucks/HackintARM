package hostdata

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestPathWindowsOpenModes(t *testing.T) {
	dir := t.TempDir()
	longDir := filepath.Join(dir, strings.Repeat("a", 100), strings.Repeat("b", 100), strings.Repeat("c", 100))
	if err := os.MkdirAll(longDir, 0700); err != nil {
		t.Fatal(err)
	}
	longFile, err := openPathOrdinary(filepath.Join(longDir, "payload"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := longFile.WriteString("long path payload"); err != nil {
		t.Fatal(err)
	}
	if err := longFile.Close(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(longDir, "payload")); err != nil || string(data) != "long path payload" {
		t.Fatal(string(data), err)
	}
	name := filepath.Join(dir, "file")
	for _, flags := range []int{os.O_CREATE | os.O_EXCL | os.O_WRONLY, os.O_CREATE | os.O_RDWR, os.O_WRONLY | os.O_APPEND, os.O_RDWR | os.O_TRUNC | os.O_APPEND | os.O_SYNC, os.O_RDONLY, os.O_WRONLY | os.O_TRUNC} {
		file, err := openPathOrdinary(name, flags, 0600)
		if err != nil {
			t.Fatalf("%x: %v", flags, err)
		}
		if flags&(os.O_WRONLY|os.O_RDWR) != 0 {
			if _, err := file.WriteString("payload"); err != nil {
				t.Fatal(err)
			}
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		want := "payload"
		if flags&os.O_APPEND != 0 && flags&os.O_TRUNC == 0 {
			want += "payload"
		}
		if data, err := os.ReadFile(name); err != nil || string(data) != want {
			t.Fatalf("open flags %x produced %q, want %q: %v", flags, data, want, err)
		}
	}
	for _, tc := range []struct {
		name  string
		flags int
		want  error
	}{
		{"", os.O_RDONLY, os.ErrNotExist}, {"bad\x00path", os.O_RDONLY, syscall.EINVAL},
		{name, os.O_CREATE | os.O_EXCL | os.O_RDWR, os.ErrExist}, {name + "missing", os.O_RDONLY, os.ErrNotExist},
		{dir, os.O_WRONLY, syscall.EISDIR}, {name, os.O_RDONLY | os.O_TRUNC, os.ErrPermission},
	} {
		file, err := openPathOrdinary(tc.name, tc.flags, 0600)
		if file != nil || !errors.Is(err, tc.want) {
			t.Fatalf("%q %x: %v %v", tc.name, tc.flags, file, err)
		}
	}
	for _, special := range []string{dir, os.DevNull} {
		file, err := openPathOrdinary(special, os.O_RDONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(name, 0444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(name, 0600) })
	original, err := os.Stat(name)
	if err != nil || !os.SameFile(original, original) {
		t.Fatal(err)
	}
	if denied, err := openPathOrdinary(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0444); denied != nil || !errors.Is(err, os.ErrPermission) {
		t.Fatal(denied, err)
	}
	after, err := os.Stat(name)
	if err != nil || !os.SameFile(original, after) {
		t.Fatalf("denied truncation replaced inode: %v", err)
	}
	if data, err := os.ReadFile(name); err != nil || string(data) != "payload" {
		t.Fatalf("denied truncation changed bytes: %q %v", data, err)
	}
	file, err := openPathOrdinary(name, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := chmodPathBacking(file, 0600); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPathWindowsOpenBoundaryFailures(t *testing.T) {
	want := errors.New("create denied")
	for _, name := range []string{filepath.Join(t.TempDir(), strings.Repeat("p", 260)), `\\server\share\` + strings.Repeat("p", 260), `\\?\C:\` + strings.Repeat("p", 260), `\\.\` + strings.Repeat("p", 260)} {
		_, err := openPathWindows(name, os.O_RDONLY, 0600, func(ptr *uint16, _, share uint32, _ *windows.SecurityAttributes, _, _ uint32, _ windows.Handle) (windows.Handle, error) {
			if share != windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE {
				t.Fatal(share)
			}
			if got := windows.UTF16PtrToString(ptr); !strings.HasPrefix(got, `\\?\`) && !strings.HasPrefix(got, `\\.\`) {
				t.Fatal(got)
			}
			return windows.InvalidHandle, want
		})
		if !errors.Is(err, want) {
			t.Fatal(err)
		}
	}
	_, err := openPathWindows(filepath.Join(t.TempDir(), "missing"), os.O_WRONLY, 0600, func(*uint16, uint32, uint32, *windows.SecurityAttributes, uint32, uint32, windows.Handle) (windows.Handle, error) {
		return windows.InvalidHandle, windows.ERROR_ACCESS_DENIED
	})
	if !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
}

func TestPathWindowsBackingFailures(t *testing.T) {
	name := filepath.Join(t.TempDir(), "backing")
	if err := os.WriteFile(name, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := openPathOrdinary(name, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	want := errors.New("reopen denied")
	err = chmodPathWindowsBacking(file, 0444, func(windows.Handle, uint32) (windows.Handle, error) { return windows.InvalidHandle, want })
	if !errors.Is(err, want) {
		t.Fatal(err)
	}
	err = chmodPathWindowsBacking(file, 0444, func(handle windows.Handle, _ uint32) (windows.Handle, error) {
		return reopenXattrHandle(handle, windows.FILE_READ_ATTRIBUTES)
	})
	if !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	if err := chmodPathBacking(nil, 0600); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := chmodPathBacking(file, 0600); err == nil {
		t.Fatal("closed backing accepted")
	}
	// The null source still reads as a device, rather than a filesystem NUL file.
	null, err := openPathOrdinary(os.DevNull, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	if _, err := null.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}
