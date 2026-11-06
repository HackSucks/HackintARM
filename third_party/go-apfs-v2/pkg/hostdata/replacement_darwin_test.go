package hostdata

import (
	"bytes"
	"errors"
	"os"

	"path/filepath"
	"syscall"
	"testing"

	heldfixture "github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"
	"golang.org/x/sys/unix"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func TestReplacementDarwinACLFlagsAndBirthTime(t *testing.T) {
	replacementVariants(t, func(t *testing.T, prepare func(*os.File, string) (*testedReplacement, error)) {
		source := heldfixture.Source(t, 0751)
		if output, err := cirunner.Command("/bin/chmod", "+a", "everyone allow read", source.Name()).CombinedOutput(); err != nil {
			t.Fatalf("chmod ACL: %v: %s", err, output)
		}
		if err := unix.Fchflags(int(source.Fd()), unix.UF_HIDDEN); err != nil {
			t.Fatal(err)
		}
		before, err := source.Stat()
		if err != nil {
			t.Fatal(err)
		}
		parent := t.TempDir()
		if output, err := cirunner.Command("/bin/chmod", "+a", "everyone allow read,file_inherit,directory_inherit", parent).CombinedOutput(); err != nil {
			t.Fatalf("parent ACL: %v: %s", err, output)
		}
		r, err := prepare(source, parent)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if _, err := r.File.WriteAt([]byte("changed"), 0); err != nil {
			t.Fatal(err)
		}
		if err := r.RestoreMetadata(); err != nil {
			t.Fatal(err)
		}
		after, err := r.File.Stat()
		if err != nil {
			t.Fatal(err)
		}
		old, new := before.Sys().(*syscall.Stat_t), after.Sys().(*syscall.Stat_t)
		if old.Birthtimespec != new.Birthtimespec || old.Flags != new.Flags {
			t.Fatalf("birth time or flags changed: %#v -> %#v", old, new)
		}
		acl := func(path string) []byte {
			out, err := cirunner.Command("/bin/ls", "-lde", path).CombinedOutput()
			if err != nil {
				t.Fatalf("read ACL: %v: %s", err, out)
			}
			_, entries, _ := bytes.Cut(out, []byte{'\n'})
			return entries
		}
		if got, want := acl(r.File.Name()), acl(source.Name()); !bytes.Equal(got, want) || len(got) == 0 {
			t.Fatalf("ACL = %q; want %q", got, want)
		}

	})
}

func TestReplacementDarwinRejectsProtectedFile(t *testing.T) {
	source := heldfixture.Source(t, 0600)
	if err := unix.Fchflags(int(source.Fd()), unix.UF_IMMUTABLE); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Chflags(source.Name(), 0) })
	path := filepath.Join(t.TempDir(), "replacement")
	if _, err := PrepareReplacement(source, filepath.Dir(path)); !errors.Is(err, ErrUnsupportedReplacement) {
		t.Fatalf("protected file: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement created: %v", err)
	}
}

func TestReplacementDarwinProtectedStages(t *testing.T) {
	source := heldfixture.Source(t, 0600)
	stagePath := t.TempDir()
	stage, err := os.OpenRoot(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	if err = unix.Fchflags(int(source.Fd()), unix.UF_IMMUTABLE); err != nil {
		t.Fatal(err)
	}
	info, err := source.Stat()
	if err != nil {
		t.Fatal(err)
	}
	file, prepareErr := prepareReplacementAtContext(t.Context(), source, stage, info)
	if err = unix.Fchflags(int(source.Fd()), 0); err != nil {
		t.Fatal(err)
	}
	if file != nil || !errors.Is(prepareErr, ErrUnsupportedReplacement) {
		t.Fatalf("protected source: %v %v", file, prepareErr)
	}
	info, err = source.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err = unix.Chflags(stagePath, unix.UF_IMMUTABLE); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := unix.Chflags(stagePath, 0); e != nil {
			t.Error(e)
		}
	})
	file, prepareErr = prepareReplacementAtContext(t.Context(), source, stage, info)
	if file != nil || !errors.Is(prepareErr, os.ErrPermission) {
		t.Fatalf("protected rooted stage: %v %v", file, prepareErr)
	}
	file, prepareErr = prepareReplacementContext(t.Context(), source, filepath.Join(stagePath, "replacement"), info)
	if file != nil || !errors.Is(prepareErr, os.ErrPermission) {
		t.Fatalf("protected path stage: %v %v", file, prepareErr)
	}
}
