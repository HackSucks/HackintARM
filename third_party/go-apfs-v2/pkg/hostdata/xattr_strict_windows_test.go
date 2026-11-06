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

// Fixture producer uses the OS wire protocol directly, separately from the
// implementation's query/removal path. Failure is fatal on the Windows runner.
func strictWindowsSet(t *testing.T, path, name string, value []byte) {
	t.Helper()
	if err := strictWindowsSetResult(t, path, name, value); err != nil {
		t.Fatalf("native set %s: %v", name, err)
	}
}

func strictWindowsSetResult(t *testing.T, path, name string, value []byte) error {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.FILE_WRITE_EA|windows.SYNCHRONIZE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	record := make([]byte, 9+len(name)+len(value))
	record[5] = byte(len(name))
	binary.LittleEndian.PutUint16(record[6:], uint16(len(value)))
	copy(record[8:], name)
	copy(record[9+len(name):], value)
	return windows.NtSetEaFile(h, &windows.IO_STATUS_BLOCK{}, &record[0], uint32(len(record)))
}

func strictWindowsFile(t *testing.T, path string) *os.File {
	t.Helper()
	if err := os.WriteFile(path, []byte("contents"), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	// A held Windows handle must share deletion for rename/hard-link identity
	// tests. os.Open deliberately omits FILE_SHARE_DELETE.
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(h), path)
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestStrictXattrWindowsLifecycle(t *testing.T) {
	for _, kind := range []string{"file", "directory"} {
		for _, length := range []int{1, 32, 1024, 4096, 60000} {
			for _, byPath := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%d/path-%t", kind, length, byPath), func(t *testing.T) {
					path := filepath.Join(t.TempDir(), "input-世界")
					var file *os.File
					if kind == "file" {
						file = strictWindowsFile(t, path)
					} else {
						if err := os.Mkdir(path, 0700); err != nil {
							t.Fatal(err)
						}
						var err error
						file, err = os.Open(path)
						if err != nil {
							t.Fatal(err)
						}
						defer file.Close()
					}
					size := func(name string) (int, bool, error) {
						if byPath {
							return XattrSizeNoFollow(path, name)
						}
						return XattrSize(file, name)
					}
					read := func(name string, n int) ([]byte, bool, error) {
						if byPath {
							return ReadXattrNoFollow(path, name, n)
						}
						return ReadXattr(file, name, n)
					}
					remove := func(name string) (bool, error) {
						if byPath {
							return RemoveXattrNoFollow(path, name)
						}
						return RemoveXattr(file, name)
					}
					name := "com.apple.ResourceFork"
					if n, p, err := size(name); n != 0 || p || err != nil {
						t.Fatal(n, p, err)
					}
					if b, p, err := read(name, length); b != nil || p || err != nil {
						t.Fatal(b, p, err)
					}
					if p, err := remove(name); p || err != nil {
						t.Fatal(p, err)
					}
					value := bytes.Repeat([]byte{0, 1, 255, 42}, (length+3)/4)[:length]
					strictWindowsSet(t, path, name, value)
					strictWindowsSet(t, path, "user.unrelated", []byte("keep"))
					if n, p, err := size(strings.ToUpper(name)); n != length || !p || err != nil {
						t.Fatal(n, p, err)
					}
					if b, p, err := read(name, length); !bytes.Equal(b, value) || !p || err != nil {
						t.Fatal(len(b), p, err)
					}
					if b, p, err := read(name, length-1); b != nil || p || !errors.Is(err, ErrXattrTooLarge) {
						t.Fatal(b, p, err)
					}
					if p, err := remove(name); !p || err != nil {
						t.Fatal(p, err)
					}
					if p, err := remove(name); p || err != nil {
						t.Fatal(p, err)
					}
					if n, p, err := size(name); n != 0 || p || err != nil {
						t.Fatal(n, p, err)
					}
					if b, p, err := read("user.unrelated", 4); string(b) != "keep" || !p || err != nil {
						t.Fatal(b, p, err)
					}
					// NTFS zero-length assignment is native deletion, not an API skip.
					strictWindowsSet(t, path, "user.unrelated", nil)
					if n, p, err := size("user.unrelated"); n != 0 || p || err != nil {
						t.Fatal(n, p, err)
					}
					if kind == "file" {
						b, err := io.ReadAll(file)
						if string(b) != "contents" || err != nil {
							t.Fatal("contents/position", b, err)
						}
					}
				})
			}
		}
	}
}

func TestStrictXattrWindowsIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "original")
	moved := filepath.Join(dir, "moved")
	alias := filepath.Join(dir, "alias")
	f := strictWindowsFile(t, path)
	strictWindowsSet(t, path, "user.strict", []byte("held"))
	if err := os.WriteFile(path+":untouched", []byte("stream"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(3, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	strictWindowsFile(t, path)
	strictWindowsSet(t, path, "user.strict", []byte("decoy"))
	if b, p, err := ReadXattr(f, "user.strict", 4); string(b) != "held" || !p || err != nil {
		t.Fatal(b, p, err)
	}
	if p, err := RemoveXattr(f, "user.strict"); !p || err != nil {
		t.Fatal(p, err)
	}
	for _, name := range []string{moved, alias} {
		if _, p, err := XattrSizeNoFollow(name, "user.strict"); p || err != nil {
			t.Fatal(name, p, err)
		}
	}
	if b, p, err := ReadXattrNoFollow(path, "user.strict", 5); string(b) != "decoy" || !p || err != nil {
		t.Fatal(b, p, err)
	}
	if b, err := os.ReadFile(moved + ":untouched"); string(b) != "stream" || err != nil {
		t.Fatal(b, err)
	}
	if n, err := f.Seek(0, io.SeekCurrent); n != 3 || err != nil {
		t.Fatal(n, err)
	}
	if b, err := os.ReadFile(moved); string(b) != "contents" || err != nil {
		t.Fatal(b, err)
	}
}

func TestStrictXattrWindowsNoFollow(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	strictWindowsFile(t, target)
	strictWindowsSet(t, target, "user.strict", []byte("target"))
	if err := os.Symlink(target, link); err != nil {
		t.Fatal("required Windows symlink fixture", err)
	}
	strictWindowsSet(t, link, "user.strict", []byte("link"))
	if b, p, err := ReadXattrNoFollow(link, "user.strict", 4); string(b) != "link" || !p || err != nil {
		t.Fatal(b, p, err)
	}
	// Hold the link, rename it, then put a different link at its former name.
	h, err := openXattrPath(link, windows.FILE_READ_EA)
	if err != nil {
		t.Fatal(err)
	}
	held := os.NewFile(uintptr(h), link)
	defer held.Close()
	moved := filepath.Join(dir, "moved-link")
	if err := os.Rename(link, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	strictWindowsSet(t, link, "user.strict", []byte("decoy"))
	if b, p, err := ReadXattr(held, "user.strict", 4); string(b) != "link" || !p || err != nil {
		t.Fatal(b, p, err)
	}
	if p, err := RemoveXattr(held, "user.strict"); !p || err != nil {
		t.Fatal(p, err)
	}
	if b, p, err := ReadXattrNoFollow(link, "user.strict", 5); string(b) != "decoy" || !p || err != nil {
		t.Fatal(b, p, err)
	}
	if b, p, err := ReadXattrNoFollow(target, "user.strict", 6); string(b) != "target" || !p || err != nil {
		t.Fatal(b, p, err)
	}
	followed, err := os.Open(link)
	if err != nil {
		t.Fatal(err)
	}
	defer followed.Close()
	if b, p, err := ReadXattr(followed, "user.strict", 6); string(b) != "target" || !p || err != nil {
		t.Fatal(b, p, err)
	}
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "absent"), dangling); err != nil {
		t.Fatal(err)
	}
	strictWindowsSet(t, dangling, "user.strict", []byte("dangling"))
	if b, p, err := ReadXattrNoFollow(dangling, "user.strict", 8); string(b) != "dangling" || !p || err != nil {
		t.Fatal(b, p, err)
	}
	if p, err := RemoveXattrNoFollow(dangling, "user.strict"); !p || err != nil {
		t.Fatal(p, err)
	}
}

func TestStrictXattrWindowsProtocol(t *testing.T) {
	for _, name := range []string{"", "bad:name", "bad\x00name", "bad\x1fname", "世界", strings.Repeat("a", 255), strings.Repeat("a", 256)} {
		if err := windowsXattrName(name); !errors.Is(err, os.ErrInvalid) {
			t.Fatal(name, err)
		}
		if _, err := queryWindowsXattr(windows.InvalidHandle, name, nil); !errors.Is(err, os.ErrInvalid) {
			t.Fatal(name, err)
		}
	}
	if _, err := openXattrPath("bad\x00path", windows.FILE_READ_EA); err == nil {
		t.Fatal("NUL path accepted")
	}
	if _, err := getVisibleXattrFD(-1, "user.strict", nil); err == nil {
		t.Fatal("invalid handle accepted")
	}
	if err := removeVisibleXattrFD(-1, "user.strict"); err == nil {
		t.Fatal("invalid handle accepted")
	}
	if _, err := queryWindowsXattr(windows.InvalidHandle, "user.strict", nil); err == nil {
		t.Fatal("invalid query accepted")
	}
	if err := removeWindowsXattr(windows.InvalidHandle, "$Kernel.protected"); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatal(err)
	}
	record := []byte{0, 0, 0, 0, 0, 3, 4, 0, 'F', 'O', 'O', 0, 'd', 'a', 't', 'a'}
	for _, r := range [][]byte{nil, record[:8], record[:15], append([]byte{1}, record[1:]...), append(append([]byte{}, record[:11]...), 'x', 'd', 'a', 't', 'a')} {
		if _, err := decodeWindowsXattr(r, "foo", nil); !errors.Is(err, windows.STATUS_EA_CORRUPT_ERROR) {
			t.Fatal(r, err)
		}
	}
	if _, err := decodeWindowsXattr(record, "bar", nil); !errors.Is(err, windows.STATUS_EA_CORRUPT_ERROR) {
		t.Fatal(err)
	}
	if _, err := decodeWindowsXattr(record, "foo", make([]byte, 3)); !errors.Is(err, windows.STATUS_BUFFER_TOO_SMALL) {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if n, err := decodeWindowsXattr(record, "foo", b); n != 4 || string(b) != "data" || err != nil {
		t.Fatal(n, b, err)
	}
	empty := append([]byte{}, record[:12]...)
	empty[6] = 0
	if _, err := decodeWindowsXattr(empty, "foo", nil); !missingXattr(err) {
		t.Fatal(err)
	}
	for _, cause := range []error{windows.STATUS_NO_EAS_ON_FILE, windows.STATUS_NONEXISTENT_EA_ENTRY, windows.STATUS_BUFFER_TOO_SMALL, windows.STATUS_BUFFER_OVERFLOW, windows.STATUS_ACCESS_DENIED} {
		calls := 0
		b, p, err := readVisibleXattr(func([]byte) (int, error) {
			calls++
			if calls == 1 {
				return 4, nil
			}
			return 0, cause
		}, 4)
		if b != nil || p || !errors.Is(err, cause) {
			t.Fatal(b, p, err)
		}
		if errors.Is(err, ErrXattrChanged) != (cause != windows.STATUS_ACCESS_DENIED) {
			t.Fatal(err)
		}
	}
	for _, cause := range []error{windows.STATUS_EAS_NOT_SUPPORTED, windows.STATUS_NOT_SUPPORTED, windows.STATUS_INVALID_DEVICE_REQUEST, windows.ERROR_NOT_SUPPORTED, windows.ERROR_INVALID_FUNCTION} {
		err := strictXattrError(cause)
		if !errors.Is(err, ErrXattrUnsupported) || !errors.Is(err, cause) {
			t.Fatal(err)
		}
	}
	if err := strictXattrError(windows.STATUS_ACCESS_DENIED); !errors.Is(err, windows.STATUS_ACCESS_DENIED) || errors.Is(err, ErrXattrUnsupported) {
		t.Fatal(err)
	}
}

func TestStrictXattrWindowsPermissionErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	file := strictWindowsFile(t, path)
	strictWindowsSet(t, path, "user.strict", []byte("keep"))
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
	sd, err := windows.SecurityDescriptorFromString("D:P(D;;0x18;;;WD)(A;;FA;;;WD)")
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
	defer func() {
		if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, savedACL, nil); err != nil {
			t.Error(err)
		}
	}()
	for name, op := range map[string]func() error{
		"descriptor-set":    func() error { return SetXattr(file, "user.strict", []byte("reject")) },
		"descriptor-list":   func() error { _, err := ListXattrNames(file, MaxXattrListSize); return err },
		"descriptor-size":   func() error { _, _, err := XattrSize(file, "user.strict"); return err },
		"descriptor-read":   func() error { _, _, err := ReadXattr(file, "user.strict", 4); return err },
		"descriptor-remove": func() error { _, err := RemoveXattr(file, "user.strict"); return err },
		"path-size":         func() error { _, _, err := XattrSizeNoFollow(path, "user.strict"); return err },
		"path-read":         func() error { _, _, err := ReadXattrNoFollow(path, "user.strict", 4); return err },
		"path-remove":       func() error { _, err := RemoveXattrNoFollow(path, "user.strict"); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := op(); !errors.Is(err, windows.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.STATUS_ACCESS_DENIED) {
				t.Fatal("EA denial suppressed", err)
			}
		})
	}
}
