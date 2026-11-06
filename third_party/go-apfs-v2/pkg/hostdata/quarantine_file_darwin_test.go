package hostdata

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	heldfixture "github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"golang.org/x/sys/unix"
)

func TestQuarantineFileNativeReadWrite(t *testing.T) {
	ctx := context.Background()
	p, err := CaptureQuarantineProcess(ctx)
	if err != nil {
		t.Fatal(err)
	}
	file := heldfixture.Source(t, 0600)
	if err := unix.Fremovexattr(int(file.Fd()), "com.apple.quarantine"); err != nil && !errors.Is(err, syscall.ENOATTR) {
		t.Fatal(err)
	}
	if absent, err := CaptureQuarantineFile(ctx, file, p.Profile); err != nil || absent != nil {
		t.Fatalf("absent: %#v %v", absent, err)
	}
	q := &appledouble.Quarantine{Flags: 1, Timestamp: 0x01020304, Agent: "SourceAgent", Identifier: "identifier"}
	if err := ApplyQuarantineFile(ctx, file, q, *p); err != nil {
		t.Fatal(err)
	}
	model, err := CaptureQuarantineFile(ctx, file, p.Profile)
	if err != nil {
		t.Fatalf("kernel capture: %v", err)
	}
	data, present, err := ReadXattr(file, "com.apple.quarantine", 4096)
	if err != nil || !present {
		t.Fatalf("readback: %t %v", present, err)
	}
	want, err := appledouble.ParseQuarantineXattrWithProfile(data, p.Profile)
	if err != nil || !reflect.DeepEqual(model, want) {
		t.Fatalf("kernel and xattr capture differ: %#v %#v %v", model, want, err)
	}
	changed := *p
	// CI may have no process label. A nonzero flag with Absent still true
	// would be malformed input, not the valid-but-stale context tested here.
	changed.Absent = false
	changed.Flags ^= 1
	if _, err := changed.Process(); err != nil {
		t.Fatalf("changed test context is invalid: %v", err)
	}
	if err := ApplyQuarantineFile(ctx, file, q, changed); !errors.Is(err, ErrQuarantineCaptureChanged) {
		t.Fatalf("changed context: %v", err)
	}
	if after, err := CaptureQuarantineFile(ctx, file, p.Profile); err != nil || !reflect.DeepEqual(after, model) {
		t.Fatalf("rejected context mutated quarantine: %#v %v", after, err)
	}
	if _, err := CaptureQuarantineFile(ctx, file, 99); !errors.Is(err, appledouble.ErrQuarantineContext) {
		t.Fatalf("profile: %v", err)
	}
	if err := ApplyQuarantineFile(ctx, file, nil, *p); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureQuarantineFile(ctx, file, p.Profile); err == nil {
		t.Fatal("closed capture")
	}
	if err := ApplyQuarantineFile(ctx, file, q, *p); err == nil {
		t.Fatal("closed apply")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := applyQuarantineFile(canceled, file, q, *p); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestQuarantineFileBoundsAndErrors(t *testing.T) {
	if unsafe.Sizeof(quarantineFileGet{}) != 24 || unsafe.Sizeof(quarantineFileSet{}) != 24 || unsafe.Offsetof(quarantineFileGet{}.data) != 16 || unsafe.Offsetof(quarantineFileSet{}.data) != 16 {
		t.Fatal("native file ABI layout")
	}
	ctx := context.Background()
	var errno int32
	a := &quarantineCaptureABI{}
	q := &appledouble.Quarantine{Flags: 1, Timestamp: 1, Agent: "source", Identifier: "id"}
	input, err := q.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	a.getFile = func(_ *byte, op int32, r *quarantineFileGet) (int32, error) {
		if op != 82 || r.fd != 123 || *r.length != 384 {
			t.Fatal("get request")
		}
		copy(unsafe.Slice(r.data, 384), input)
		*r.length = uint64(len(input) - 1)
		return 0, nil
	}
	got, err := a.readFile(ctx, 123, 0)
	if err != nil || !reflect.DeepEqual(got, q) {
		t.Fatalf("get model: %#v %v", got, err)
	}
	a.setFile = func(_ *byte, op int32, r *quarantineFileSet) (int32, error) {
		if op != 83 || r.fd != 123 || string(unsafe.Slice(r.data, int(r.length))) != string(input) {
			t.Fatal("set request")
		}
		return 0, nil
	}
	if err := a.writeFile(ctx, 123, q, 0); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := a.readFile(canceled, 123, 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := a.writeFile(canceled, 123, q, 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := a.writeFile(ctx, 123, &appledouble.Quarantine{Flags: 1 << 24}, 0); !errors.Is(err, appledouble.ErrQuarantine) {
		t.Fatal(err)
	}
	if err := a.writeFile(ctx, 123, &appledouble.Quarantine{Flags: 1, Agent: strings.Repeat("\xff", 255)}, 0); !errors.Is(err, appledouble.ErrQuarantineApplicationSize) {
		t.Fatal(err)
	}
	a.getFile = func(*byte, int32, *quarantineFileGet) (int32, error) { return -1, syscall.Errno(errno) }
	errno = int32(syscall.EPERM)
	if _, err := a.readFile(ctx, 123, 0); !errors.Is(err, syscall.EPERM) {
		t.Fatal(err)
	}
	errno = int32(syscall.ENOATTR)
	if model, err := a.readFile(ctx, 123, 0); err != nil || model != nil {
		t.Fatal(err)
	}
	a.setFile = func(*byte, int32, *quarantineFileSet) (int32, error) { return -1, syscall.Errno(errno) }
	if err := a.writeFile(ctx, 123, nil, 0); !errors.Is(err, syscall.ENOATTR) {
		t.Fatal(err)
	}
	a.getFile = func(_ *byte, _ int32, r *quarantineFileGet) (int32, error) { *r.length = 385; return 0, nil }
	if _, err := a.readFile(ctx, 123, 0); !errors.Is(err, appledouble.ErrQuarantine) {
		t.Fatal(err)
	}
	a.getFile = func(_ *byte, _ int32, r *quarantineFileGet) (int32, error) {
		for i := range 384 {
			unsafe.Slice(r.data, 384)[i] = 'x'
		}
		return 0, nil
	}
	if _, err := a.readFile(ctx, 123, 0); !errors.Is(err, appledouble.ErrQuarantine) {
		t.Fatal(err)
	}
	a.getFile = func(_ *byte, _ int32, r *quarantineFileGet) (int32, error) {
		copy(unsafe.Slice(r.data, 384), "invalid")
		*r.length = 7
		return 0, nil
	}
	if _, err := a.readFile(ctx, 123, 0); !errors.Is(err, appledouble.ErrQuarantine) {
		t.Fatal(err)
	}
	interrupted, stop := context.WithCancel(ctx)
	a.getFile = func(*byte, int32, *quarantineFileGet) (int32, error) { stop(); return 0, nil }
	if _, err := a.readFile(interrupted, 123, 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
