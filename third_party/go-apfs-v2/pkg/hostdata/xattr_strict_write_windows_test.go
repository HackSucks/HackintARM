package hostdata

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// Read the wire value independently of the production named-read decoder.
func strictWriteNativeRead(t *testing.T, path, name string, want []byte) {
	t.Helper()
	h, err := openXattrPath(path, windows.FILE_READ_EA)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	query := make([]byte, 6+len(name))
	query[4] = byte(len(name))
	copy(query[5:], name)
	raw := make([]byte, 128<<10)
	var status windows.IO_STATUS_BLOCK
	err = windows.NtQueryEaFile(h, &status, &raw[0], uint32(len(raw)), true, &query[0], uint32(len(query)), nil, true)
	if len(want) == 0 && (errors.Is(err, windows.STATUS_NONEXISTENT_EA_ENTRY) || errors.Is(err, windows.STATUS_NO_EAS_ON_FILE)) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if status.Information < 9 || status.Information > uintptr(len(raw)) {
		t.Fatal(status.Information)
	}
	raw = raw[:status.Information]
	n := int(raw[5])
	size := int(binary.LittleEndian.Uint16(raw[6:]))
	if n+9+size > len(raw) || raw[8+n] != 0 || !strings.EqualFold(string(raw[8:8+n]), name) || !bytes.Equal(raw[9+n:9+n+size], want) {
		t.Fatalf("native read differs: name=%s size=%d want=%x", name, size, want)
	}
}

func TestStrictXattrWriteWindows(t *testing.T) {
	for _, kind := range []string{"file", "directory"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input")
			var f *os.File
			if kind == "file" {
				f = strictWindowsFile(t, path)
			} else {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				h, err := openXattrPath(path, windows.FILE_READ_EA)
				if err != nil {
					t.Fatal(err)
				}
				f = os.NewFile(uintptr(h), path)
				defer f.Close()
			}
			strictWindowsSet(t, path, "user.keep", []byte("keep"))
			for _, value := range [][]byte{nil, {0, 1, 255}, {}, bytes.Repeat([]byte{42}, 60000), {7}, nil} {
				before := bytes.Clone(value)
				if err := SetXattr(f, "user.write", value); err != nil {
					t.Fatal(err)
				}
				strictWriteNativeRead(t, path, "USER.WRITE", value)
				if !bytes.Equal(value, before) {
					t.Fatal("input changed")
				}
			}
			moved := path + "-moved"
			if err := os.Rename(path, moved); err != nil {
				t.Fatal(err)
			}
			strictWindowsFile(t, path)
			strictWindowsSet(t, path, "user.write", []byte("decoy"))
			if err := SetXattr(f, "user.write", []byte("held")); err != nil {
				t.Fatal(err)
			}
			strictWriteNativeRead(t, moved, "user.write", []byte("held"))
			strictWriteNativeRead(t, path, "user.write", []byte("decoy"))
			strictWriteNativeRead(t, moved, "user.keep", []byte("keep"))
			if kind == "file" {
				alias := path + "-alias"
				if err := os.Link(moved, alias); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(moved+":untouched", []byte("stream"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := SetXattr(f, "USER.WRITE", []byte("alias")); err != nil {
					t.Fatal(err)
				}
				strictWriteNativeRead(t, alias, "user.write", []byte("alias"))
				if b, err := io.ReadAll(f); err != nil || string(b) != "contents" {
					t.Fatal("contents/offset", b, err)
				}
				if b, err := os.ReadFile(moved + ":untouched"); err != nil || string(b) != "stream" {
					t.Fatal(b, err)
				}
			}
		})
	}
}

func TestStrictXattrWriteWindowsBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bounds")
	f := strictWindowsFile(t, path)
	name := strings.Repeat("n", 254)
	if err := SetXattr(f, name, []byte("keep")); err != nil {
		t.Fatal(err)
	}
	strictWriteNativeRead(t, path, name, []byte("keep"))
	for _, name := range []string{strings.Repeat("n", 255), "bad:name", "世界"} {
		if err := SetXattr(f, name, []byte{1}); !errors.Is(err, os.ErrInvalid) {
			t.Fatal(name, err)
		}
	}
	for _, name := range []string{"$Kernel.protected", "$KERNEL.P"} {
		if err := SetXattr(f, name, []byte{1}); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			t.Fatal(err)
		}
	}
	if err := SetXattr(f, name, make([]byte, 65536)); !errors.Is(err, ErrXattrTooLarge) {
		t.Fatal(err)
	}
	strictWriteNativeRead(t, path, name, []byte("keep"))
	if err := setVisibleXattrFD(-1, "user.valid", []byte{1}); err == nil {
		t.Fatal("invalid handle succeeded")
	}
	if err := assignWindowsXattr(windows.InvalidHandle, "user.valid", []byte{1}); err == nil {
		t.Fatal("invalid write succeeded")
	}
	// The wire permits 65535 bytes, but the filesystem's record/aggregate limits
	// may be smaller. Compare with direct native assignment on a separate fixture.
	for _, size := range []int{65500, 65535} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			dir := t.TempDir()
			actual := filepath.Join(dir, "go")
			reference := filepath.Join(dir, "native")
			file := strictWindowsFile(t, actual)
			strictWindowsFile(t, reference)
			value := bytes.Repeat([]byte{0xab}, size)
			native := strictWindowsSetResult(t, reference, "user.bound", value)
			err := SetXattr(file, "user.bound", value)
			if !errors.Is(err, native) {
				t.Fatal("native boundary differs", err, native)
			}
			if err == nil {
				strictWriteNativeRead(t, actual, "user.bound", value)
			}
			t.Logf("value length %d: native=%v Go=%v", size, native, err)
		})
	}
}

func TestStrictXattrWriteWindowsLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	strictWindowsFile(t, target)
	strictWindowsSet(t, target, "user.write", []byte("target"))
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	h, err := openXattrPath(link, windows.FILE_READ_EA)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(h), link)
	defer f.Close()
	moved := link + "-moved"
	if err := os.Rename(link, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	strictWindowsSet(t, link, "user.write", []byte("decoy"))
	if err := SetXattr(f, "user.write", []byte("held")); err != nil {
		t.Fatal(err)
	}
	strictWriteNativeRead(t, moved, "user.write", []byte("held"))
	strictWriteNativeRead(t, link, "user.write", []byte("decoy"))
	strictWriteNativeRead(t, target, "user.write", []byte("target"))
	followed, err := os.Open(link)
	if err != nil {
		t.Fatal(err)
	}
	defer followed.Close()
	if err := SetXattr(followed, "user.write", []byte("followed")); err != nil {
		t.Fatal(err)
	}
	strictWriteNativeRead(t, target, "user.write", []byte("followed"))
	strictWriteNativeRead(t, moved, "user.write", []byte("held"))
}

func TestStrictXattrWriteWindowsWithoutRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "write-only")
	file := strictWindowsFile(t, path)
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	saved, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	savedACL, _, err := saved.DACL()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(D;;0x8;;;WD)(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	denied, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, denied, nil); err != nil {
		t.Fatal(err)
	}
	restore := func() {
		if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, savedACL, nil); err != nil {
			t.Fatal(err)
		}
	}
	defer restore()
	if _, _, err := ReadXattr(file, "user.write", 100); !errors.Is(err, windows.STATUS_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatal("read denial not active", err)
	}
	if err := SetXattr(file, "user.write", []byte("write without read")); err != nil {
		t.Fatal("write unnecessarily requires read", err)
	}
	restore()
	strictWriteNativeRead(t, path, "user.write", []byte("write without read"))
}
