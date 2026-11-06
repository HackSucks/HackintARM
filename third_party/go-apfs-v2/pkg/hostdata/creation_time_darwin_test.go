package hostdata

import (
	"bytes"
	"errors"
	"os"

	"path/filepath"
	"syscall"
	"testing"
	"time"

	heldfixture "github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"
	"golang.org/x/sys/unix"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func TestSetCreationTimeDarwinHeldFile(t *testing.T) {
	file := heldfixture.Source(t, 0640)
	original, moved := file.Name(), file.Name()+".moved"
	if out, err := cirunner.Command("/bin/chmod", "+a", "everyone allow read", original).CombinedOutput(); err != nil {
		t.Fatalf("ACL: %v: %s", err, out)
	}
	if err := unix.Fsetxattr(int(file.Fd()), "org.example.creation", []byte("retained"), 0); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fchflags(int(file.Fd()), unix.UF_HIDDEN); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(original, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(original, []byte("neighbour"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(original), "linked")
	if err := os.Link(moved, link); err != nil {
		t.Fatal(err)
	}
	neighbour, err := os.Stat(original)
	if err != nil {
		t.Fatal(err)
	}
	acl := func() []byte {
		out, err := cirunner.Command("/bin/ls", "-lde", moved).CombinedOutput()
		if err != nil {
			t.Fatal(err)
		}
		_, value, _ := bytes.Cut(out, []byte{'\n'})
		return value
	}
	beforeACL := acl()
	content, err := os.ReadFile(moved)
	if err != nil {
		t.Fatal(err)
	}
	// Stat after reading the content, which may move the access time.
	before, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	when := time.Unix(946684800, 123456789)
	if err := SetCreationTime(file, when); err != nil {
		t.Fatal(err)
	}
	after, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	old, got := *before.Sys().(*syscall.Stat_t), *after.Sys().(*syscall.Stat_t)
	if got.Birthtimespec.Sec != when.Unix() || got.Birthtimespec.Nsec != int64(when.Nanosecond()) {
		t.Fatalf("creation time: %v", got.Birthtimespec)
	}
	old.Birthtimespec, old.Ctimespec = got.Birthtimespec, got.Ctimespec
	if old != got || !bytes.Equal(beforeACL, acl()) {
		t.Fatalf("unrelated metadata changed: %#v -> %#v", old, got)
	}
	other, err := os.Stat(original)
	if err != nil {
		t.Fatal(err)
	}
	if *neighbour.Sys().(*syscall.Stat_t) != *other.Sys().(*syscall.Stat_t) {
		t.Fatal("reused source pathname changed")
	}
	linked, err := os.Stat(link)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(after, linked) || linked.Sys().(*syscall.Stat_t).Birthtimespec != got.Birthtimespec {
		t.Fatal("hard-link identity or time changed")
	}
	value := make([]byte, 32)
	n, err := unix.Fgetxattr(int(file.Fd()), "org.example.creation", value)
	if err != nil || string(value[:n]) != "retained" {
		t.Fatalf("xattr: %v", err)
	}
	gotContent, err := os.ReadFile(moved)
	if err != nil || !bytes.Equal(gotContent, content) {
		t.Fatalf("contents changed: %v", err)
	}
}

func TestSetCreationTimeDarwinFuture(t *testing.T) {
	file := heldfixture.Source(t, 0600)
	before, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	when := time.Now().Add(48 * time.Hour)
	if err := SetCreationTime(file, when); err != nil {
		t.Fatal(err)
	}
	after, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	old, got := *before.Sys().(*syscall.Stat_t), *after.Sys().(*syscall.Stat_t)
	if got.Birthtimespec.Sec != when.Unix() || got.Birthtimespec.Nsec != int64(when.Nanosecond()) {
		t.Fatalf("creation time: %v", got.Birthtimespec)
	}
	old.Birthtimespec, old.Ctimespec = got.Birthtimespec, got.Ctimespec
	if old != got {
		t.Fatalf("unrelated metadata changed: %#v -> %#v", old, got)
	}
}

func TestSetCreationTimeDarwinProtectedFile(t *testing.T) {
	file := heldfixture.Source(t, 0600)
	if err := unix.Fchflags(int(file.Fd()), unix.UF_IMMUTABLE); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Chflags(file.Name(), 0) })
	before, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := SetCreationTime(file, time.Unix(946684800, 0)); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("protected update: %v", err)
	}
	after, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if *before.Sys().(*syscall.Stat_t) != *after.Sys().(*syscall.Stat_t) {
		t.Fatal("failed update changed metadata")
	}
}
