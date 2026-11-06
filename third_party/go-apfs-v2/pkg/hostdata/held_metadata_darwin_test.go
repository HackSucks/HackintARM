package hostdata

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
	"golang.org/x/sys/unix"
)

func TestHeldMetadataNative(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h, err := NewHeldMetadata(f)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.DisableCache(); err != nil {
		t.Fatal(err)
	}
	original, err := h.CaptureStat()
	if err != nil {
		t.Fatal(err)
	}
	s, err := h.CaptureSecurity()
	if err != nil || s.UID != original.UID || s.Mode != original.Mode {
		t.Fatal(s, err)
	}
	if s.Properties.UID == nil || s.Properties.Mode == nil {
		t.Fatal(s)
	}
	cap, err := CaptureSecuritySource(h.SourceCapture())
	if err != nil || !cap.Completed {
		t.Fatal(cap, err)
	}
	if err = h.Chmod(0640); err != nil {
		t.Fatal(err)
	}
	if err = h.Chown(original.UID, original.GID); err != nil {
		t.Fatal(err)
	}
	modify, access := time.Unix(1700000000, 12345), time.Unix(1700000001, 54321)
	if err = h.SetTimes(modify, access); err != nil {
		t.Fatal(err)
	}
	if err = setFileTimes(f, modify, access); err != nil {
		t.Fatal(err)
	}
	stat, err := h.CaptureStat()
	if err != nil || !stat.Times.Modify.Equal(modify) || !stat.Times.Access.Equal(access) || stat.Mode&0777 != 0640 {
		t.Fatal(stat, err)
	}
	if err = h.Chflags(original.Flags | unix.UF_HIDDEN); err != nil {
		t.Fatal(err)
	}
	flags, err := h.ReadFlags()
	if err != nil || flags&unix.UF_HIDDEN == 0 {
		t.Fatal(flags, err)
	}
	actual, err := h.CompareAndSwapFlags(flags, original.Flags)
	if err != nil || actual != flags {
		t.Fatal(actual, err)
	}
	actual, err = h.CompareAndSwapFlags(flags, original.Flags)
	if err != nil || actual != original.Flags {
		t.Fatal(actual, err)
	}
	a, err := h.CaptureACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = h.WriteACL(a); err != nil {
		t.Fatal(err)
	}
	if _, err = h.CaptureDestinationACL(); err != nil {
		t.Fatal(err)
	}
	if err = h.SetACL(&appledouble.ACL{}); err != nil {
		t.Fatal(err)
	}
	if err = h.SetACL(nil); err != nil {
		t.Fatal(err)
	}
	if err = h.WriteSecurity(aclmeta.DarwinChmodArguments{UID: 0xffffff9b, GID: 0xffffff9b, Mode: -1}); err != nil {
		t.Fatal(err)
	}
	if err = h.WriteACL(aclmeta.ACLMetadata{}); err == nil {
		t.Fatal("invalid ACL accepted")
	}
	if err = h.SetACL(&appledouble.ACL{Entries: make([]appledouble.ACLEntry, 129)}); err == nil {
		t.Fatal("invalid ACL accepted")
	}
	if err = h.WriteSecurity(aclmeta.DarwinChmodArguments{SecurityArgument: 8}); err == nil {
		t.Fatal("invalid arguments accepted")
	}
	// Renaming and replacing the original name must never redirect operations.
	if err = os.Rename(path, path+"-held"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err = h.Chmod(0644); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatal(fi, err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = h.CaptureSecurity(); err == nil {
		t.Fatal("closed descriptor accepted")
	}
	prior := SecuritySourceStat{UID: 42}
	got, err := h.SourceCapture().ReadStat(prior)
	if err == nil || got != prior {
		t.Fatal(got, err)
	}
	if _, err = NewHeldMetadata(f); err == nil {
		t.Fatal("closed file accepted")
	}
}

func TestHeldMetadataNativeErrors(t *testing.T) {
	if _, err := newHeldMetadata(nil); err == nil {
		t.Fatal("nil native descriptor accepted")
	}
	if err := (&nativeHeldMetadata{}).control(func(int32) error { return nil }); err == nil {
		t.Fatal("nil descriptor control accepted")
	}
	invalid := os.NewFile(0x7fffffff, "invalid")
	defer invalid.Close()
	if _, err := (&nativeHeldMetadata{file: invalid}).CaptureStat(); !errors.Is(err, syscall.EBADF) {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(t.TempDir(), "held")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var eno int32
	a := &darwinSecurityABI{init: func() uintptr { return 1 }, free: func(uintptr) {}, stat: func(int32, *unix.Stat_t, uintptr) (int32, error) { return -1, syscall.Errno(eno) }, chmod: func(int32, uint32, uint32, int32, uintptr) (int32, error) { return -1, syscall.Errno(eno) }, fsctl: func(int32, uintptr, unsafe.Pointer, uint32) (int32, error) { return -1, syscall.Errno(eno) }}
	m := &nativeHeldMetadata{file: f, abi: a}
	for _, e := range []syscall.Errno{syscall.ENOTSUP, syscall.EPERM, syscall.EIO} {
		eno = int32(e)
		_, err = m.CaptureSecurity()
		if !errors.Is(err, e) {
			t.Fatal(err)
		}
	}
	a.init = func() uintptr { return 0 }
	if _, err = m.CaptureSecurity(); !errors.Is(err, syscall.ENOMEM) {
		t.Fatal(err)
	}
	eno = int32(syscall.ENOTSUP)
	if err = m.WriteSecurity(aclmeta.DarwinChmodArguments{Mode: -1}); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal(err)
	}
	eno = int32(syscall.EAGAIN)
	if _, err = m.CompareAndSwapFlags(0, 1); !errors.Is(err, ErrStatFlagsAgain) {
		t.Fatal(err)
	}
	a.stat = func(int32, *unix.Stat_t, uintptr) (int32, error) { return 0, nil }
	a.init = func() uintptr { return 1 }
	a.get = func(uintptr, int32, unsafe.Pointer) (int32, error) {
		eno = int32(syscall.EIO)
		return -1, syscall.Errno(eno)
	}
	if _, err = m.CaptureSecurity(); !errors.Is(err, syscall.EIO) {
		t.Fatal(err)
	}
	// Pin an already closed descriptor: SyscallConn creation and Control are
	// separately fallible and neither may call into libSystem after close.
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if err = m.Chflags(0); err == nil {
		t.Fatal("closed accepted")
	}
}

func TestDarwinSecurityProperties(t *testing.T) {
	raw, _ := (&appledouble.FileSecurity{ACL: &appledouble.ACL{}, Trailing: make([]byte, 24)}).MarshalDarwinBinary()
	var eno int32
	makeABI := func(fail int32, missing bool) *darwinSecurityABI {
		return &darwinSecurityABI{get: func(_ uintptr, name int32, out unsafe.Pointer) (int32, error) {
			if name == fail {
				if missing {
					eno = int32(syscall.ENOENT)
				} else {
					eno = int32(syscall.EIO)
				}
				return -1, syscall.Errno(eno)
			}
			switch name {
			case 1, 2:
				*(*uint32)(out) = 501
			case 4:
				*(*uint16)(out) = 0644
			case 3, 6:
				*(*[16]byte)(out) = [16]byte{1}
			case 100:
				*(*unsafe.Pointer)(out) = unsafe.Pointer(unsafe.SliceData(raw))
			case 101:
				*(*uintptr)(out) = uintptr(len(raw))
			}
			return 0, nil
		}}
	}
	for _, property := range []int32{1, 2, 4, 3, 6, 100, 101} {
		if _, err := makeABI(property, false).properties(1); !errors.Is(err, syscall.EIO) {
			t.Fatal(property, err)
		}
		_, err := makeABI(property, true).properties(1)
		if property == 101 {
			if !errors.Is(err, appledouble.ErrFileSecurity) {
				t.Fatal(err)
			}
		} else if err != nil {
			t.Fatal(property, err)
		}
	}
	p, err := makeABI(-1, false).properties(1)
	if err != nil || p.RawSecurity == nil || len(p.RawSecurity.Trailing) != 0 || p.Mode == nil || *p.Mode != 0644 {
		t.Fatal(p, err)
	}
	for _, value := range [][]byte{nil, make([]byte, 1), make([]byte, 44)} {
		raw = value
		if _, err = makeABI(-1, false).properties(1); !errors.Is(err, appledouble.ErrFileSecurity) {
			t.Fatal(err)
		}
	}
}

func TestDarwinSecurityBinding(t *testing.T) {
	a, err := loadDarwinSecurity()
	if err != nil {
		t.Fatal(err)
	}
	sec := a.init()
	if sec == 0 {
		t.Fatal("filesec allocation")
	}
	defer a.free(sec)
	var st unix.Stat_t
	if n, err := a.stat(-1, &st, sec); n != -1 || !errors.Is(err, syscall.EBADF) {
		t.Fatal(n, err)
	}
}
