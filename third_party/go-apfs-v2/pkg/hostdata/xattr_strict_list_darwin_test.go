package hostdata

import (
	"errors"
	"os"

	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func TestStrictXattrListDarwinVisibility(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if e := os.WriteFile(path, []byte("data"), 0600); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	for _, nonzero := range []bool{true, false} {
		finder := make([]byte, 32)
		fork := []byte{}
		if nonzero {
			finder[0] = 1
			fork = []byte{7}
		}
		strictSetXattr(t, path, "com.apple.FinderInfo", finder)
		if !nonzero {
			if e := unix.Lremovexattr(path, ResourceForkName); e != nil {
				t.Fatal(e)
			}
		}
		strictSetXattr(t, path, ResourceForkName, fork)
		if nonzero {
			strictSetXattr(t, path, ResourceForkName, nil)
			value, present, err := ReadXattr(f, ResourceForkName, 1)
			if err != nil || !present || string(value) != string([]byte{7}) {
				t.Fatal("empty assignment changed existing fork", value, present, err)
			}
		}
		names, e := ListXattrNames(f, MaxXattrListSize)
		if e != nil || slices.Contains(names, "com.apple.FinderInfo") != nonzero || slices.Contains(names, ResourceForkName) != nonzero {
			t.Fatal(nonzero, names, e)
		}
	}
	if out, e := cirunner.Command("/bin/chmod", "+a", "everyone allow read", path).CombinedOutput(); e != nil {
		t.Fatal(e, string(out))
	}
	t.Cleanup(func() { _ = cirunner.Command("/bin/chmod", "-N", path).Run() })
	if names, e := ListXattrNames(f, MaxXattrListSize); e != nil || slices.Contains(names, SecurityName) {
		t.Fatal("security visibility", names, e)
	}
	if out, e := cirunner.Command("/bin/chmod", "+a", "everyone deny readextattr", path).CombinedOutput(); e != nil {
		t.Fatal(e, string(out))
	}
	if names, e := ListXattrNames(f, MaxXattrListSize); names != nil || (!errors.Is(e, unix.EACCES) && !errors.Is(e, unix.EPERM)) {
		t.Fatal("permission suppressed", names, e)
	}
}
func TestStrictXattrListDarwinLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if e := os.WriteFile(target, []byte("data"), 0600); e != nil {
		t.Fatal(e)
	}
	strictSetXattr(t, target, "user.target", []byte{1})
	if e := os.Symlink(target, link); e != nil {
		t.Fatal(e)
	}
	strictSetXattr(t, link, "user.link", []byte{2})
	fd, e := unix.Open(link, unix.O_RDONLY|unix.O_SYMLINK|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	held := os.NewFile(uintptr(fd), link)
	defer held.Close()
	want, e := ListXattrNames(held, MaxXattrListSize)
	if e != nil || !slices.Contains(want, "user.link") || slices.Contains(want, "user.target") {
		t.Fatal(want, e)
	}
	if e := os.Rename(link, link+"-moved"); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(target, link); e != nil {
		t.Fatal(e)
	}
	strictSetXattr(t, link, "user.decoy", []byte{3})
	if n, e := ListXattrNames(held, MaxXattrListSize); e != nil || !reflect.DeepEqual(n, want) {
		t.Fatal(n, e)
	}
}
