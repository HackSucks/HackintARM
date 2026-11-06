package hostdata

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func TestStrictXattrDarwinNativeValues(t *testing.T) {
	for _, tc := range []struct {
		name    string
		value   []byte
		present bool
	}{
		{ResourceForkName, nil, false}, {ResourceForkName, []byte("resource fork"), true},
		{"com.apple.FinderInfo", append([]byte("TEXTttxt"), make([]byte, 24)...), true},
		{"com.apple.FinderInfo", make([]byte, 32), false},
		{"user.strict", nil, true}, {"user.strict", []byte("native value"), true},
	} {
		t.Run(fmt.Sprintf("%s/%d", tc.name, len(tc.value)), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input")
			if err := os.WriteFile(path, []byte("contents"), 0600); err != nil {
				t.Fatal(err)
			}
			if out, err := cirunner.Command("/usr/bin/xattr", "-wx", tc.name, hex.EncodeToString(tc.value), path).CombinedOutput(); err != nil {
				t.Fatal(err, string(out))
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if !tc.present {
				// APFS normalizes empty ResourceFork and all-zero FinderInfo to
				// absence; an ordinary present-empty attribute below stays present.
				if n, present, err := XattrSize(file, tc.name); n != 0 || present || err != nil {
					t.Fatal(n, present, err)
				}
				if data, present, err := ReadXattr(file, tc.name, len(tc.value)); data != nil || present || err != nil {
					t.Fatal(data, present, err)
				}
				if out, err := cirunner.Command("/usr/bin/xattr", "-px", tc.name, path).CombinedOutput(); err == nil {
					t.Fatal("native exposes normalized-away value", string(out))
				}
				return
			}
			if n, present, err := XattrSize(file, tc.name); n != len(tc.value) || !present || err != nil {
				t.Fatal(n, present, err)
			}
			if got, present, err := ReadXattr(file, tc.name, len(tc.value)); !present || !bytes.Equal(got, tc.value) || err != nil {
				t.Fatal(got, present, err)
			}
			out, err := cirunner.Command("/usr/bin/xattr", "-px", tc.name, path).CombinedOutput()
			if err != nil {
				t.Fatal(err, string(out))
			}
			native, err := hex.DecodeString(strings.Join(strings.Fields(string(out)), ""))
			if err != nil || !bytes.Equal(native, tc.value) {
				t.Fatal(string(out), err)
			}
			if removed, err := RemoveXattr(file, tc.name); !removed || err != nil {
				t.Fatal(removed, err)
			}
			if out, err := cirunner.Command("/usr/bin/xattr", "-px", tc.name, path).CombinedOutput(); err == nil {
				t.Fatal("native still reads removed attribute", string(out))
			}
		})
	}
}

func TestStrictXattrDarwinLinkDescriptor(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("content"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", link); err != nil {
		t.Fatal(err)
	}
	strictSetXattr(t, target, "user.strict", []byte("target"))
	strictSetXattr(t, link, "user.strict", []byte("link"))
	fd, err := unix.Open(link, unix.O_RDONLY|unix.O_SYMLINK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), link)
	defer file.Close()
	if got, present, err := ReadXattr(file, "user.strict", 4); string(got) != "link" || !present || err != nil {
		t.Fatal(string(got), present, err)
	}
	if err := os.Rename(link, filepath.Join(dir, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", link); err != nil {
		t.Fatal(err)
	}
	strictSetXattr(t, link, "user.strict", []byte("decoy"))
	if removed, err := RemoveXattr(file, "user.strict"); !removed || err != nil {
		t.Fatal(removed, err)
	}
	if _, present, err := XattrSize(file, "user.strict"); present || err != nil {
		t.Fatal(present, err)
	}
	if got, present, err := ReadXattrNoFollow(link, "user.strict", 5); string(got) != "decoy" || !present || err != nil {
		t.Fatal(string(got), present, err)
	}
	if got, present, err := ReadXattrNoFollow(target, "user.strict", 6); string(got) != "target" || !present || err != nil {
		t.Fatal(string(got), present, err)
	}
}

func TestStrictXattrDarwinPermissionErrors(t *testing.T) {
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
	if out, err := cirunner.Command("/bin/chmod", "+a", "everyone deny readextattr,writeextattr", path).CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	t.Cleanup(func() { _ = cirunner.Command("/bin/chmod", "-N", path).Run() })
	for _, read := range []func() error{
		func() error { _, _, err := XattrSize(file, "user.strict"); return err },
		func() error { _, _, err := ReadXattr(file, "user.strict", 4); return err },
		func() error { _, _, err := XattrSizeNoFollow(path, "user.strict"); return err },
		func() error { _, _, err := ReadXattrNoFollow(path, "user.strict", 4); return err },
		func() error { _, err := RemoveXattr(file, "user.strict"); return err },
		func() error { _, err := RemoveXattrNoFollow(path, "user.strict"); return err },
	} {
		if err := read(); !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPERM) {
			t.Fatal("permission error suppressed", err)
		}
	}
	if out, err := cirunner.Command("/bin/chmod", "-N", path).CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	if got, present, err := ReadXattr(file, "user.strict", 4); string(got) != "keep" || !present || err != nil {
		t.Fatal(got, present, err)
	}
}
