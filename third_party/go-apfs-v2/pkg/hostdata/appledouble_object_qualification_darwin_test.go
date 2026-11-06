package hostdata

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"testing"

	heldfixture "github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"golang.org/x/sys/unix"
)

func TestAppleDoubleObjectNativeAttributes(t *testing.T) {
	ctx := context.Background()
	file := heldfixture.Source(t, 0600)
	object, err := NewHostAppleDoubleObject(ctx, file)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := object.LogicalSnapshot(); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal(err)
	}
	a := object.attrs.(*hostObjectAttributes)
	if err := a.write("user.object.fixture", []byte("metadata")); err != nil {
		t.Fatal(err)
	}
	size, err := a.listSize()
	if err != nil || size <= 0 {
		t.Fatal(size, err)
	}
	names, err := a.names(size)
	if err != nil || !slices.Contains(names, "user.object.fixture") {
		t.Fatal(names, err)
	}
	if got, err := a.size("user.object.fixture"); err != nil || got != 8 {
		t.Fatal(got, err)
	}
	value := make([]byte, 8)
	if n, err := a.read("user.object.fixture", value); err != nil || n != 8 || string(value) != "metadata" {
		t.Fatal(n, err)
	}
	for _, capacity := range []int{-1, MaxXattrListSize + 1, 1} {
		if _, err := a.names(capacity); err == nil {
			t.Fatal("invalid name capacity", capacity)
		}
	}
	if err := a.remove("user.object.fixture"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.size("user.object.fixture"); err == nil {
		t.Fatal("removed attribute remains")
	}
	if _, err := a.noSetID(); err != nil {
		t.Fatal(err)
	}
	if err := a.control(func(int) error { return unix.EPERM }); !errors.Is(err, ErrXattrRestoreNotPermitted) || !errors.Is(err, unix.EPERM) {
		t.Fatal(err)
	}
	if err := (&hostObjectAttributes{}).control(func(int) error { return nil }); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	q := &appledouble.Quarantine{Flags: 1, Timestamp: 123, Agent: "ObjectFixture", Identifier: "fixed"}
	if err := a.applyQuarantine(ctx, q, object.process, 123); err != nil {
		t.Fatal(err)
	}
	if got, err := a.quarantine(ctx, object.process.Profile); err != nil || got == nil {
		t.Fatal(got, err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.listSize(); err == nil {
		t.Fatal("closed descriptor accepted")
	}
}

func TestAppleDoubleObjectNativeVolumeFailure(t *testing.T) {
	file := heldfixture.Source(t, 0600)
	a := &hostObjectAttributes{file: file}
	// Invalidate only this owned descriptor, without opening anything before
	// releasing os.File ownership. This exercises actual fstatfs failure.
	if err := unix.Close(int(file.Fd())); err != nil {
		t.Fatal(err)
	}
	_, err := a.noSetID()
	_ = file.Close()
	if !errors.Is(err, unix.EBADF) {
		t.Fatal(err)
	}
}

func TestAppleDoubleObjectNativeHeldRoundTrip(t *testing.T) {
	ctx := context.Background()
	sourceFile := heldfixture.Source(t, 0600)
	packedFile, err := os.CreateTemp(t.TempDir(), "packed-")
	if err != nil {
		t.Fatal(err)
	}
	defer packedFile.Close()
	targetFile := heldfixture.Source(t, 0600)
	source, err := NewHostAppleDoubleObject(ctx, sourceFile)
	if err != nil {
		t.Fatal(err)
	}
	packed, err := NewHostAppleDoubleObject(ctx, packedFile)
	if err != nil {
		t.Fatal(err)
	}
	target, err := NewHostAppleDoubleObject(ctx, targetFile)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"user.object": "ordinary", appledouble.ResourceForkName: "fork-data"} {
		if err := source.attrs.write(name, []byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	if err := target.attrs.write("user.stale", []byte("remove")); err != nil {
		t.Fatal(err)
	}
	if err := targetFile.Chmod(0400); err != nil {
		t.Fatal(err)
	}
	options := DefaultObjectPackOptions()
	options.NoCache = true
	p, err := PackAppleDoubleObject(ctx, source, packed, packedFile, options)
	if err != nil || !p.Pack.HeaderWritten || !p.Lifecycle.ModeRestored {
		t.Fatal(p, err)
	}
	info, err := packedFile.Stat()
	if err != nil {
		t.Fatal(err)
	}
	input := io.NewSectionReader(packedFile, 0, info.Size())
	u, err := UnpackAppleDoubleObject(ctx, input, packed, target, DefaultObjectUnpackOptions())
	if err != nil || !u.Unpack.ReachedEnd || !u.Lifecycle.ModeRestored {
		t.Fatal(u, err)
	}
	for name, want := range map[string]string{"user.object": "ordinary", appledouble.ResourceForkName: "fork-data"} {
		got := make([]byte, len(want))
		if n, err := target.attrs.read(name, got); err != nil || n != len(want) || !bytes.Equal(got, []byte(want)) {
			t.Fatal(name, n, err)
		}
	}
	if _, err := target.attrs.size("user.stale"); err == nil {
		t.Fatal("destination cleanup omitted")
	}
	info, err = targetFile.Stat()
	if err != nil || info.Mode().Perm() != 0400 {
		t.Fatal(info, err)
	}
}

func TestAppleDoubleObjectNativeTruncateFork(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "fork")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	a := &hostObjectAttributes{file: f}
	if err := a.write(appledouble.ResourceForkName, []byte("owned fork")); err != nil {
		t.Fatal(err)
	}
	if err := a.truncateFork(0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.size(appledouble.ResourceForkName); !missingXattr(err) {
		t.Fatal("native fork not truncated", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := a.truncateFork(0600); err == nil {
		t.Fatal("closed source accepted")
	}
}
