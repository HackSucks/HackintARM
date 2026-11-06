package hostdata

import (
	"context"
	"errors"
	"reflect"
	"syscall"
	"testing"
	"unsafe"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestQuarantineCaptureDarwinABI(t *testing.T) {
	var info quarantineProcessInfo
	if unsafe.Sizeof(info) != 64 || unsafe.Offsetof(info.agent) != 8 || unsafe.Offsetof(info.metadata) != 24 || unsafe.Offsetof(info.tracking) != 40 || unsafe.Offsetof(info.flags) != 48 || unsafe.Offsetof(info.pid) != 56 {
		t.Fatal("native process-info layout differs")
	}
	for _, release := range []string{"26.0.0", "27.0.0"} {
		if _, err := nativeQuarantineProfile(release); err != nil {
			t.Fatal(err)
		}
	}
	for _, release := range []string{"", "15.7.1", "25.0.0", "28.0.0", "26.invalid"} {
		if _, err := nativeQuarantineProfile(release); !errors.Is(err, errors.ErrUnsupported) {
			t.Fatal(err)
		}
	}
	a, err := loadQuarantineCapture()
	if err != nil {
		t.Fatal(err)
	}
	got, err := CaptureQuarantineProcess(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	independent, err := a.read(got.Profile)
	if err != nil || !reflect.DeepEqual(got, independent) {
		t.Fatalf("native repeated snapshot differs: %v", err)
	}
	// Native library capture independently confirms whether the self label is absent.
	if err := a.confirmAbsent(); got.Absent && err != nil || !got.Absent && !errors.Is(err, ErrQuarantineCaptureChanged) {
		t.Fatalf("independent native capture status: %v", err)
	}
}

func TestQuarantineCaptureDarwinBoundsAndErrors(t *testing.T) {
	marker := errors.New("capture provider failure")
	if _, err := captureNativeQuarantineUsing(context.Background(), func() (string, error) { return "", marker }, nil); !errors.Is(err, marker) {
		t.Fatal(err)
	}
	if _, err := captureNativeQuarantineUsing(context.Background(), func() (string, error) { return "28.0", nil }, nil); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := captureNativeQuarantineUsing(context.Background(), func() (string, error) { return "27.0", nil }, func() (*quarantineCaptureABI, error) { return nil, marker }); !errors.Is(err, marker) {
		t.Fatal(err)
	}
	var errno int32
	a := &quarantineCaptureABI{}
	a.query = func(_ *byte, operation int32, i *quarantineProcessInfo) (int32, error) {
		if operation != 84 || i.pid != 0 || i.reserved != 0 {
			t.Fatal("not a valid self query")
		}
		copy(unsafe.Slice(i.agent, 257), []byte{'A', '\\', 0xff})
		i.agentLength = 3
		copy(unsafe.Slice(i.metadata, 65), []byte{0, 1})
		i.metadataLength = 2
		copy(unsafe.Slice(i.tracking, 64), []byte{2, 0})
		i.trackingLength = 2
		i.flags = 0x200
		return 0, nil
	}
	got, err := a.read(appledouble.QuarantineMacOS27)
	if err != nil || string(got.Agent) != "A\\\xff" || len(got.Metadata) != 2 || len(got.Tracking) != 2 || got.Flags != 0x200 {
		t.Fatalf("raw capture: %#v %v", got, err)
	}
	for _, mutate := range []func(*quarantineProcessInfo){func(i *quarantineProcessInfo) { i.agentLength = 256 }, func(i *quarantineProcessInfo) { i.metadataLength = 65 }, func(i *quarantineProcessInfo) { i.trackingLength = 65 }, func(i *quarantineProcessInfo) { i.flags = 1 << 32 }} {
		a.query = func(_ *byte, _ int32, i *quarantineProcessInfo) (int32, error) { mutate(i); return 0, nil }
		if _, err := a.read(0); !errors.Is(err, appledouble.ErrQuarantineContext) {
			t.Fatal(err)
		}
	}
	a.query = func(*byte, int32, *quarantineProcessInfo) (int32, error) { return -1, syscall.Errno(errno) }
	errno = int32(syscall.EPERM)
	if _, err := a.read(0); !errors.Is(err, syscall.EPERM) {
		t.Fatal(err)
	}
	errno = int32(syscall.ENOATTR)
	if c, err := a.read(0); err != nil || !c.Absent {
		t.Fatal(err)
	}
	a.alloc = func() uintptr { return 0 }
	if err := a.confirmAbsent(); !errors.Is(err, syscall.ENOMEM) {
		t.Fatal(err)
	}
	a.alloc = func() uintptr { return 1 }
	freed := 0
	a.free = func(uintptr) { freed++ }
	a.capture = func(uintptr) (int32, error) { return -1, syscall.Errno(errno) }
	if err := a.confirmAbsent(); err != nil {
		t.Fatal(err)
	}
	errno = int32(syscall.EPERM)
	if err := a.confirmAbsent(); !errors.Is(err, syscall.EPERM) {
		t.Fatal(err)
	}
	a.capture = func(uintptr) (int32, error) { return 0, nil }
	if err := a.confirmAbsent(); !errors.Is(err, ErrQuarantineCaptureChanged) {
		t.Fatal(err)
	}
	if freed != 3 {
		t.Fatalf("native allocations not freed: %d", freed)
	}
}
