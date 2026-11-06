package darwinabi

import (
	"encoding/json"
	"errors"
	"os"

	"path/filepath"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func TestTypedSecurityAndContextWrappers(t *testing.T) {
	sec := FilesecInit()
	if sec == 0 {
		t.Fatal("filesec allocation")
	}
	defer FilesecFree(sec)
	f, err := os.CreateTemp(t.TempDir(), "metadata")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var st unix.Stat_t
	if _, err := Fstatx(int32(f.Fd()), &st, sec); err != nil {
		t.Fatal(err)
	}
	var uid uint32
	if _, err := FilesecGetProperty(sec, 1, unsafe.Pointer(&uid)); err != nil || uid != uint32(os.Getuid()) {
		t.Fatal(uid, err)
	}
	if _, err := Fstatx(-1, &st, sec); !errors.Is(err, syscall.EBADF) {
		t.Fatal(err)
	}
	process := QuarantineProcessAlloc()
	if process == 0 {
		t.Fatal("quarantine allocation")
	}
	defer QuarantineProcessFree(process)
	if _, err := QuarantineProcessInit(process); err != nil && !errors.Is(err, syscall.ENOATTR) {
		t.Fatal(err)
	}
	_ = AppSandboxed()
}

// These calls check the native -1/errno convention through each typed boundary,
// including fd and path operations whose successful calls run in hostdata tests.
func TestTypedNativeErrors(t *testing.T) {
	if n, err := Flistxattr(-1, nil, 0, 0); n != 0 || !errors.Is(err, syscall.EBADF) {
		t.Fatal(n, err)
	}
	if n, err := FchmodExtended(-1, ^uint32(0), ^uint32(0), 0600, 0); n != -1 || !errors.Is(err, syscall.EBADF) {
		t.Fatal(n, err)
	}
	path, err := unix.BytePtrFromString(t.TempDir() + "/absent")
	if err != nil {
		t.Fatal(err)
	}
	if n, err := ChmodExtended(path, ^uint32(0), ^uint32(0), 0600, 0); n != -1 || !errors.Is(err, syscall.ENOENT) {
		t.Fatal(n, err)
	}
	var request [12]byte
	if n, err := Ffsctl(-1, 0xc00c4114, unsafe.Pointer(&request), 0); n != -1 || !errors.Is(err, syscall.EBADF) {
		t.Fatal(n, err)
	}
}

func TestTypedHeldErrors(t *testing.T) {
	name, err := unix.BytePtrFromString("com.apple.ResourceFork")
	if err != nil {
		t.Fatal(err)
	}
	if n, err := Fsetxattr(-1, name, nil, 0, 0, 0); n != -1 || !errors.Is(err, syscall.EBADF) {
		t.Fatal(n, err)
	}

	if n, err := Fgetxattr(-1, name, nil, 0, 0, 0); n != 0 || !errors.Is(err, syscall.EBADF) {
		t.Fatalf("fgetxattr: size=%d err=%v", n, err)
	}
	list := unix.Attrlist{Bitmapcount: 5, Commonattr: unix.ATTR_CMN_CRTIME}
	value := unix.Timespec{Sec: 1700000000, Nsec: 1234}
	if n, err := Fsetattrlist(-1, &list, unsafe.Pointer(&value), unsafe.Sizeof(value), 0); n != -1 || !errors.Is(err, syscall.EBADF) {
		t.Fatalf("fsetattrlist: status=%d err=%v", n, err)
	}
}

// Call the actual protected-open entry point even on filesystems where the
// higher-level API correctly chooses ordinary open. The independent C result
// determines native support and errno; neither outcome is skipped or invented.
func TestTypedProtectedOpenNative(t *testing.T) {
	oracle := os.Getenv("APFS_DARWIN_WRAPPERS_ORACLE")
	if oracle == "" {
		oracle = filepath.Join(t.TempDir(), "darwin-wrappers")
		source := filepath.Join("..", "..", "testdata", "appledouble", "native", "darwin-wrappers.c")
		if out, err := cirunner.Command("xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-DDARWIN_WRAPPERS_ORACLE", source, "-o", oracle).CombinedOutput(); err != nil {
			t.Fatalf("compile native observer: %v\n%s", err, out)
		}
	}
	directory := t.TempDir()
	existing := filepath.Join(directory, "existing")
	if err := os.WriteFile(existing, []byte("typed wrapper payload"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"existing", "missing"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, name)
			output, err := cirunner.Command(oracle, path).Output()
			if err != nil {
				t.Fatalf("native observation: %v", err)
			}
			var want struct {
				Success bool `json:"success"`
				Errno   int  `json:"errno"`
			}
			if err := json.Unmarshal(output, &want); err != nil {
				t.Fatal(err)
			}
			if want.Success && want.Errno != 0 || !want.Success && want.Errno == 0 {
				t.Fatalf("invalid native observation: %s", output)
			}
			p, err := unix.BytePtrFromString(path)
			if err != nil {
				t.Fatal(err)
			}
			fd, err := OpenDprotected(p, unix.O_RDONLY, -1, 0, 0)
			if fd >= 0 {
				defer unix.Close(int(fd))
			}
			if !want.Success {
				if fd != -1 || !errors.Is(err, syscall.Errno(want.Errno)) {
					t.Fatalf("protected open: fd=%d err=%v, native=%s", fd, err, output)
				}
				t.Logf("native and Go errno=%d", want.Errno)
				return
			}
			if err != nil || fd < 0 {
				t.Fatalf("protected open: fd=%d err=%v, native=%s", fd, err, output)
			}
			var actual, expected unix.Stat_t
			if err := unix.Fstat(int(fd), &actual); err != nil {
				t.Fatal(err)
			}
			if err := unix.Stat(path, &expected); err != nil {
				t.Fatal(err)
			}
			if actual.Dev != expected.Dev || actual.Ino != expected.Ino || actual.Mode != expected.Mode {
				t.Fatalf("protected open returned a different object: %+v != %+v", actual, expected)
			}
			var payload [64]byte
			n, err := unix.Read(int(fd), payload[:])
			if err != nil {
				t.Fatalf("readback: %v", err)
			}
			if string(payload[:n]) != "typed wrapper payload" {
				t.Fatalf("readback: %q", payload[:n])
			}
			t.Log("native and Go protected opens succeeded with matching identity and payload")
		})
	}
}

func TestTypedHeldPath(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "held-path")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var path [unix.PathMax]byte
	if n, err := FcntlGetPath(int32(file.Fd()), &path); n != 0 || err != nil {
		t.Fatal(n, err)
	}
	before, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	actual, err := os.Stat(unix.ByteSliceToString(path[:]))
	if err != nil || !os.SameFile(before, actual) {
		t.Fatal("held path identity", err)
	}
	if err = os.Rename(file.Name(), file.Name()+".moved"); err != nil {
		t.Fatal(err)
	}
	if n, err := FcntlGetPath(int32(file.Fd()), &path); n != 0 || err != nil {
		t.Fatal(n, err)
	}
	actual, err = os.Stat(unix.ByteSliceToString(path[:]))
	if err != nil || !os.SameFile(before, actual) {
		t.Fatal("renamed held path identity", err)
	}
	if n, err := FcntlGetPath(-1, &path); n != -1 || !errors.Is(err, syscall.EBADF) {
		t.Fatal(n, err)
	}
}

func TestTypedVolumeCapabilities(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "volume")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	list := unix.Attrlist{Bitmapcount: 5, Volattr: unix.ATTR_VOL_INFO | unix.ATTR_VOL_CAPABILITIES}
	var result [9]uint32
	if status, err := Fgetattrlist(int32(file.Fd()), &list, unsafe.Pointer(&result), unsafe.Sizeof(result), 0); status != 0 || err != nil || result[0] != uint32(unsafe.Sizeof(result)) {
		t.Fatal(status, result, err)
	}
	if status, err := Fgetattrlist(-1, &list, unsafe.Pointer(&result), unsafe.Sizeof(result), 0); status != -1 || !errors.Is(err, syscall.EBADF) {
		t.Fatal(status, err)
	}
}
