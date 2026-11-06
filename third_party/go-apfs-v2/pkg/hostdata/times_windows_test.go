package hostdata

import (
	heldfixture "github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"
	accesstime "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/accesstime"

	"errors"
	"os"
	"syscall"
	"testing"
	"time"

	hosttime "github.com/deploymenttheory/go-apfs-v2/internal/hosttime"
	"golang.org/x/sys/windows"
)

func TestCarrierWindowsHeldTimes(t *testing.T) {
	source, readOnlyTarget := heldfixture.Source(t, 0600), heldfixture.Source(t, 0600)
	// SetFileTime requires FILE_WRITE_ATTRIBUTES on the held handle. Confirm
	// a read-only handle is refused, then exercise the authorized handle.
	if err := accesstime.CopyAccessTime(source, readOnlyTarget); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("read-only target: %v", err)
	}
	target, err := openTimeTestFile(readOnlyTarget.Name(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	when := time.Unix(978307200, 234567800)
	if err := os.Chtimes(source.Name(), when, when.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	from, err := source.Stat()
	if err != nil {
		t.Fatal(err)
	}
	before, err := target.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := accesstime.CopyAccessTime(source, target); err != nil {
		t.Fatal(err)
	}
	if err := SetCreationTime(target, when); err != nil {
		t.Fatal(err)
	}
	after, err := target.Stat()
	if err != nil {
		t.Fatal(err)
	}
	want, got := *before.Sys().(*syscall.Win32FileAttributeData), *after.Sys().(*syscall.Win32FileAttributeData)
	ticks, err := hosttime.WindowsTicks(when)
	if err != nil {
		t.Fatal(err)
	}
	if got.CreationTime.LowDateTime != uint32(ticks) || got.CreationTime.HighDateTime != uint32(ticks>>32) || got.LastAccessTime != from.Sys().(*syscall.Win32FileAttributeData).LastAccessTime {
		t.Fatal("native times differ")
	}
	want.CreationTime, want.LastAccessTime = got.CreationTime, got.LastAccessTime
	if want != got {
		t.Fatal("unrelated metadata changed")
	}
	if err := SetCreationTime(target, when.Add(time.Nanosecond)); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("precision: %v", err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	stamp := windows.Filetime{LowDateTime: 1}
	if err := hosttime.SetWindows(target, &stamp, nil, nil); err == nil {
		t.Fatalf("closed: %v", err)
	}
	if err := hosttime.SetWindows(nil, &stamp, nil, nil); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nil: %v", err)
	}
}
