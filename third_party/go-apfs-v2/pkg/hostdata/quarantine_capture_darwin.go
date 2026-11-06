package hostdata

import (
	"context"
	"errors"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/deploymenttheory/go-apfs-v2/internal/darwinabi"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
	"golang.org/x/sys/unix"
)

// Matches the independently measured libquarantine 217 process-info ABI in
// testdata/appledouble/native/quarantine-process-capture.h. Only the libSystem
// wrapper crosses the boundary; no numbered syscall or policy algorithm does.
type quarantineProcessInfo struct {
	agentLength    uint64
	agent          *byte
	metadataLength uint64
	metadata       *byte
	trackingLength uint64
	tracking       *byte
	flags          uint64
	pid            int32
	reserved       uint32
}

type quarantineCaptureABI struct {
	query   func(*byte, int32, *quarantineProcessInfo) (int32, error)
	getFile func(*byte, int32, *quarantineFileGet) (int32, error)
	setFile func(*byte, int32, *quarantineFileSet) (int32, error)
	alloc   func() uintptr
	free    func(uintptr)
	capture func(uintptr) (int32, error)
}

var loadQuarantineCapture = func() (*quarantineCaptureABI, error) {
	return &quarantineCaptureABI{
		query: func(policy *byte, operation int32, data *quarantineProcessInfo) (int32, error) {
			return darwinabi.MacSyscall(policy, operation, unsafe.Pointer(data))
		},
		getFile: func(policy *byte, operation int32, data *quarantineFileGet) (int32, error) {
			return darwinabi.MacSyscall(policy, operation, unsafe.Pointer(data))
		},
		setFile: func(policy *byte, operation int32, data *quarantineFileSet) (int32, error) {
			return darwinabi.MacSyscall(policy, operation, unsafe.Pointer(data))
		},
		alloc: darwinabi.QuarantineProcessAlloc, free: darwinabi.QuarantineProcessFree, capture: darwinabi.QuarantineProcessInit,
	}, nil
}

func nativeQuarantineProfile(release string) (appledouble.QuarantineProfile, error) {
	version, err := osversion.Parse(release)
	if err != nil {
		return 0, errors.Join(errors.ErrUnsupported, err)
	}
	profile, err := osversion.ProfileForMacOS(version)
	if err != nil {
		return 0, errors.Join(errors.ErrUnsupported, err)
	}
	switch profile {
	case osversion.MacOS26:
		return appledouble.QuarantineMacOS26, nil
	case osversion.MacOS27:
		return appledouble.QuarantineMacOS27, nil
	default:
		return 0, errors.ErrUnsupported
	}
}

func captureNativeQuarantineProcess(ctx context.Context) (*QuarantineProcessCapture, error) {
	return captureNativeQuarantineUsing(ctx, func() (string, error) { return unix.Sysctl("kern.osproductversion") }, loadQuarantineCapture)
}

func captureNativeQuarantineUsing(ctx context.Context, version func() (string, error), load func() (*quarantineCaptureABI, error)) (*QuarantineProcessCapture, error) {
	release, err := version()
	if err != nil {
		return nil, err
	}
	profile, err := nativeQuarantineProfile(release)
	if err != nil {
		return nil, err
	}
	a, err := load()
	if err != nil {
		return nil, err
	}
	return captureQuarantineProcess(ctx, func() (*QuarantineProcessCapture, error) { return a.read(profile) }, a.confirmAbsent)
}

func (a *quarantineCaptureABI) read(profile appledouble.QuarantineProfile) (*QuarantineProcessCapture, error) {
	var agent [257]byte
	var metadata [65]byte
	var tracking [64]byte
	i := quarantineProcessInfo{agent: &agent[0], metadata: &metadata[0], tracking: &tracking[0]}
	policy := []byte("Quarantine\x00")
	_, err := a.query(&policy[0], 84, &i)
	runtime.KeepAlive(policy)
	runtime.KeepAlive(agent)
	runtime.KeepAlive(metadata)
	runtime.KeepAlive(tracking)
	if errors.Is(err, syscall.ENOATTR) {
		return &QuarantineProcessCapture{Profile: profile, Absent: true}, nil
	}
	if err != nil {
		return nil, err
	}
	if i.agentLength > 255 || i.metadataLength > 64 || i.trackingLength > 64 || i.flags > 1<<32-1 {
		return nil, appledouble.ErrQuarantineContext
	}
	return &QuarantineProcessCapture{Profile: profile, Flags: uint32(i.flags), Agent: agent[:i.agentLength], Metadata: metadata[:i.metadataLength], Tracking: tracking[:i.trackingLength]}, nil
}

func (a *quarantineCaptureABI) confirmAbsent() error {
	p := a.alloc()
	if p == 0 {
		return syscall.ENOMEM
	}
	defer a.free(p)
	_, err := a.capture(p)
	if errors.Is(err, syscall.ENOATTR) {
		return nil
	}
	if err == nil {
		return ErrQuarantineCaptureChanged
	}
	return err
}
