package hostdata

import (
	"bytes"
	"context"
	"errors"
	"os"
	"runtime"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"golang.org/x/sys/unix"
)

// The qtn file wrappers use three 64-bit slots, as independently inspected in
// libquarantine and asserted by the C oracle. Get uses a length pointer; Set a
// length value. Both use a sign-extended descriptor, never a pathname.
type quarantineFileGet struct {
	fd     int64
	length *uint64
	data   *byte
}
type quarantineFileSet struct {
	fd     int64
	length uint64
	data   *byte
}

func quarantineHostABI(profile appledouble.QuarantineProfile) (*quarantineCaptureABI, error) {
	release, err := unix.Sysctl("kern.osproductversion")
	if err != nil {
		return nil, err
	}
	actual, err := nativeQuarantineProfile(release)
	if err != nil {
		return nil, err
	}
	if actual != profile {
		return nil, appledouble.ErrQuarantineContext
	}
	return loadQuarantineCapture()
}

func captureQuarantineFile(ctx context.Context, file *os.File, profile appledouble.QuarantineProfile) (*appledouble.Quarantine, error) {
	a, err := quarantineHostABI(profile)
	if err != nil {
		return nil, err
	}
	var model *appledouble.Quarantine
	err = withXattrDescriptor(file, func(fd int) error {
		var err error
		model, err = a.readFile(ctx, fd, profile)
		return err
	})
	return model, err
}

func (a *quarantineCaptureABI) readFile(ctx context.Context, fd int, profile appledouble.QuarantineProfile) (*appledouble.Quarantine, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var buffer [384]byte
	n := uint64(len(buffer))
	request := quarantineFileGet{fd: int64(fd), length: &n, data: &buffer[0]}
	policy := []byte("Quarantine\x00")
	_, err := a.getFile(&policy[0], 82, &request)
	runtime.KeepAlive(policy)
	runtime.KeepAlive(buffer)
	if errors.Is(err, syscall.ENOATTR) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if n > uint64(len(buffer)) {
		return nil, appledouble.ErrQuarantine
	}
	// The native length excludes the terminating NUL. Include its bounded
	// slot when reproducing libquarantine's strlen before parsing.
	end := bytes.IndexByte(buffer[:min(n+1, uint64(len(buffer)))], 0)
	if end < 0 {
		return nil, appledouble.ErrQuarantine
	}
	return appledouble.ParseQuarantineWithProfile(buffer[:end+1], profile)
}

func applyQuarantineFile(ctx context.Context, file *os.File, source *appledouble.Quarantine, process QuarantineProcessCapture) error {
	actual, err := CaptureQuarantineProcess(ctx)
	if err != nil {
		return err
	}
	if actual.Profile != process.Profile || actual.Flags != process.Flags || actual.Absent != process.Absent || !bytes.Equal(actual.Agent, process.Agent) || !bytes.Equal(actual.Metadata, process.Metadata) || !bytes.Equal(actual.Tracking, process.Tracking) {
		return ErrQuarantineCaptureChanged
	}
	a, err := loadQuarantineCapture()
	if err != nil {
		return err
	}
	return withXattrDescriptor(file, func(fd int) error { return a.writeFile(ctx, fd, source, process.Profile) })
}

func (a *quarantineCaptureABI) writeFile(ctx context.Context, fd int, source *appledouble.Quarantine, profile appledouble.QuarantineProfile) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data := []byte("q/\x00")
	if source != nil {
		var err error
		data, err = source.MarshalBinaryWithProfile(profile)
		if err != nil {
			return err
		}
		if len(data) > appledouble.MaxQuarantineApplicationSize+3 {
			return appledouble.ErrQuarantineApplicationSize
		}
	}
	request := quarantineFileSet{fd: int64(fd), length: uint64(len(data)), data: &data[0]}
	policy := []byte("Quarantine\x00")
	_, err := a.setFile(&policy[0], 83, &request)
	runtime.KeepAlive(policy)
	runtime.KeepAlive(data)
	return err
}
