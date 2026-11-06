package hostdata

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
	"golang.org/x/sys/unix"
)

func TestPathNativeMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	f, err := OpenProtectedPath(path, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR, -1, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = f.WriteString("payload"); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("file", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("missing", filepath.Join(dir, "dangling")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"file", "link", "dangling", "."} {
		p := filepath.Join(dir, name)
		m, err := CapturePathMetadata(p, true)
		if err != nil {
			t.Fatal(name, err)
		}
		var st unix.Stat_t
		if err = unix.Lstat(p, &st); err != nil {
			t.Fatal(err)
		}
		if m.Identity.Inode != st.Ino || m.Identity.Device != uint64(st.Dev) || m.State.Stat.Mode != uint32(st.Mode) || m.Size != st.Size {
			t.Fatal(name, m, st)
		}
	}
	a, err := CapturePathMetadata(path, false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CapturePathMetadata(filepath.Join(dir, "link"), false)
	if err != nil || a.Identity != b.Identity {
		t.Fatal(a, b, err)
	}
	mode := uint32(0640)
	if err = WritePathSecurity(filepath.Join(dir, "link"), aclmeta.DarwinChmodProperties{Mode: &mode, RawSecurity: &appledouble.FileSecurity{ACL: &appledouble.ACL{Entries: []appledouble.ACLEntry{{Principal: [16]byte{1}, Flags: 1, Rights: 2}}}}}); err != nil {
		t.Fatal(err)
	}
	a, err = CapturePathMetadata(path, true)
	if err != nil || a.State.Stat.Mode&0777 != 0640 || a.State.Security.Properties.RawSecurity == nil || len(a.State.Security.Properties.RawSecurity.ACL.Entries) != 1 {
		t.Fatal(a, err)
	}
	if err = WritePathSecurity(path, aclmeta.DarwinChmodProperties{RemoveACL: true}); err != nil {
		t.Fatal(err)
	}
	if _, err = CapturePathMetadata(path+"\x00", false); !errors.Is(err, unix.EINVAL) {
		t.Fatal(err)
	}
	if err = WritePathSecurity(path+"\x00", aclmeta.DarwinChmodProperties{}); !errors.Is(err, unix.EINVAL) {
		t.Fatal(err)
	}
	if err = WritePathSecurity(path, aclmeta.DarwinChmodProperties{RemoveACL: true, RawSecurity: &appledouble.FileSecurity{}}); err == nil {
		t.Fatal("invalid properties")
	}
	if _, err = CapturePathMetadata(filepath.Join(dir, "missing"), false); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if _, err = OpenProtectedPath(path, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR, -1, 0600); !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	var st unix.Statfs_t
	if err = unix.Fstatfs(int(f.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	want := st.Flags&unix.MNT_CPROTECT != 0
	if got, err := FileProtectionSupport(f); err != nil || got != want {
		t.Fatal(got, err)
	}
	for _, p := range []string{path, filepath.Join(dir, "new")} {
		if got, err := PathProtectionSupport(p); err != nil || got != want {
			t.Fatal(got, err)
		}
	}
	class, e := ReadProtectionClass(f)
	nativeClass, nativeErr := unix.FcntlInt(f.Fd(), unix.F_GETPROTECTIONCLASS, 0)
	if class != nativeClass || !errors.Is(e, nativeErr) {
		t.Fatal(class, e, nativeClass, nativeErr)
	}
	if nativeErr == nil {
		if err = SetProtectionClass(f, class); err != nil {
			t.Fatal(err)
		}
	} else {
		if err = SetProtectionClass(f, 0); err == nil {
			t.Fatal("class change unexpectedly succeeded on unsupported profile")
		}
	}
	if _, err = FileProtectionSupport(nil); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if _, err = ReadProtectionClass(nil); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if err = SetProtectionClass(nil, 0); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	invalid := os.NewFile(0x7fffffff, "invalid")
	defer invalid.Close()
	if _, err = FileProtectionSupport(invalid); !errors.Is(err, unix.EBADF) {
		t.Fatal(err)
	}
}

func TestPathNativeProviderErrors(t *testing.T) {
	var eno int32 = 5
	a := &darwinPathABI{security: &darwinSecurityABI{init: func() uintptr { return 0 }}}
	if _, err := a.capture("file", false); !errors.Is(err, ErrFilesecAllocation) || !errors.Is(err, unix.ENOMEM) {
		t.Fatal(err)
	}
	a.security.init = func() uintptr { return 1 }
	a.security.free = func(uintptr) {}
	a.stat = func(*byte, *unix.Stat_t, uintptr) (int32, error) { return -1, syscall.Errno(eno) }
	if _, err := a.capture("file", false); !errors.Is(err, unix.EIO) {
		t.Fatal(err)
	}
	a.stat = func(*byte, *unix.Stat_t, uintptr) (int32, error) { return 0, nil }
	a.security.get = func(uintptr, int32, unsafe.Pointer) (int32, error) { return -1, syscall.Errno(eno) }
	if _, err := a.capture("file", false); !errors.Is(err, unix.EIO) {
		t.Fatal(err)
	}
	old := loadDarwinPath
	loadDarwinPath = func() (*darwinPathABI, error) { return nil, unix.EIO }
	defer func() { loadDarwinPath = old }()
	if _, err := CapturePathMetadata("file", false); !errors.Is(err, unix.EIO) {
		t.Fatal(err)
	}
	if err := WritePathSecurity("file", aclmeta.DarwinChmodProperties{}); !errors.Is(err, unix.EIO) {
		t.Fatal(err)
	}
}

func TestPathNativeProtectionProviders(t *testing.T) {
	for _, tt := range []struct {
		first, second error
		want          bool
		err           error
	}{{nil, nil, true, nil}, {unix.ENOENT, nil, true, nil}, {unix.ENOENT, unix.EIO, false, unix.EIO}, {unix.EPERM, nil, false, unix.EPERM}} {
		calls := 0
		got, err := pathProtectionSupport("parent/leaf", func(path string, st *unix.Statfs_t) error {
			calls++
			st.Flags = unix.MNT_CPROTECT
			if calls == 1 {
				return tt.first
			}
			if path != "parent" {
				t.Fatal(path)
			}
			return tt.second
		})
		if got != tt.want || !errors.Is(err, tt.err) {
			t.Fatal(tt, got, err)
		}
	}
	f, err := os.CreateTemp(t.TempDir(), "protected")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var eno int32 = 5
	a := &darwinPathABI{security: &darwinSecurityABI{}}
	probe := func(string) (bool, error) { return true, nil }
	load := func() (*darwinPathABI, error) { return a, nil }
	if _, err = openProtectedPath("file", 0, 0, 0600, probe, unix.Open, func() (*darwinPathABI, error) { return nil, unix.EIO }); !errors.Is(err, unix.EIO) {
		t.Fatal(err)
	}
	if _, err = openProtectedPath("bad\x00", 0, 0, 0600, probe, unix.Open, load); !errors.Is(err, unix.EINVAL) {
		t.Fatal(err)
	}
	a.protectedOpen = func(*byte, int32, int32, int32, uint32) (int32, error) { return -1, syscall.Errno(eno) }
	if _, err = openProtectedPath("file", 0, 0, 0600, probe, unix.Open, load); !errors.Is(err, unix.EIO) {
		t.Fatal(err)
	}
	for _, flags := range []int{0, unix.O_CREAT} {
		a.protectedOpen = func(_ *byte, gotFlags, class, dpflags int32, mode uint32) (int32, error) {
			want := uint32(0)
			if flags&unix.O_CREAT != 0 {
				want = 0640
			}
			if gotFlags != int32(flags) || class != 3 || dpflags != 0 || mode != want {
				t.Fatal(gotFlags, class, dpflags, mode)
			}
			fd, err := unix.Dup(int(f.Fd()))
			if err != nil {
				t.Fatal(err)
			}
			return int32(fd), nil
		}
		file, err := openProtectedPath("file", flags, 3, 0640, probe, unix.Open, load)
		if err != nil {
			t.Fatal(err)
		}
		if err = file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	file, err := openProtectedPath(f.Name(), unix.O_RDONLY, 3, 0, func(string) (bool, error) { return false, syscall.EPERM }, unix.Open, load)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
}
