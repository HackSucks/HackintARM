package hostdata

import (
	"bytes"
	"context"
	"errors"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// ErrQuarantineCaptureChanged means two native observations disagreed. It is
// never evidence of an absent process label.
var ErrQuarantineCaptureChanged = errors.New("quarantine process changed during capture")

// QuarantineProcessCapture owns the raw effective process label. Byte slices
// preserve binary agents/metadata/tracking through JSON's base64 encoding. It
// contains no inferred local user identity. Tracking is opaque preservation
// data and should not be logged. A snapshot grants no native authorization.
type QuarantineProcessCapture struct {
	Profile                   appledouble.QuarantineProfile
	Flags                     uint32
	Agent, Metadata, Tracking []byte
	Absent                    bool
}

// Process supplies the portable application planner with exact raw agent bytes.
// A valid capture can still describe a policy context the planner has not
// qualified; that operation returns ErrQuarantineContext rather than inventing
// behavior. Linux and Windows can consume captures without native dependencies.
func (c QuarantineProcessCapture) Process() (*appledouble.QuarantineProcess, error) {
	if c.Profile != appledouble.QuarantineMacOS26 && c.Profile != appledouble.QuarantineMacOS27 || len(c.Agent) > 255 || len(c.Metadata) > 64 || len(c.Tracking) > 64 {
		return nil, appledouble.ErrQuarantineContext
	}
	if c.Absent && (c.Flags != 0 || len(c.Agent)+len(c.Metadata)+len(c.Tracking) != 0) {
		return nil, appledouble.ErrQuarantineContext
	}
	return &appledouble.QuarantineProcess{Flags: c.Flags, Agent: string(c.Agent), Absent: c.Absent}, nil
}

// CaptureQuarantineProcess reads this process's effective raw quarantine label
// on qualified macOS 26/27 hosts. It never alters process state
// or queries another PID. Unknown native ABIs and other hosts return
// errors.ErrUnsupported; callers on those hosts supply an explicit captured
// QuarantineProcessCapture to the portable planner/carrier instead.
//
// Two raw observations must agree. Absence additionally requires independent
// libquarantine capture to return ENOATTR. Callers must exclude concurrent label
// changes; repeated reads detect observed changes, not change-and-revert races.
func CaptureQuarantineProcess(ctx context.Context) (*QuarantineProcessCapture, error) {
	if ctx == nil {
		return nil, os.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return captureNativeQuarantineProcess(ctx)
}

func captureQuarantineProcess(ctx context.Context, query func() (*QuarantineProcessCapture, error), confirmAbsent func() error) (*QuarantineProcessCapture, error) {
	first, err := query()
	if err != nil {
		return nil, err
	}
	if first == nil {
		return nil, appledouble.ErrQuarantineContext
	}
	if _, err := first.Process(); err != nil {
		return nil, err
	}
	if first.Absent {
		if err := confirmAbsent(); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	second, err := query()
	if err != nil {
		return nil, err
	}
	if second == nil || first.Profile != second.Profile || first.Flags != second.Flags || first.Absent != second.Absent || !bytes.Equal(first.Agent, second.Agent) || !bytes.Equal(first.Metadata, second.Metadata) || !bytes.Equal(first.Tracking, second.Tracking) {
		return nil, ErrQuarantineCaptureChanged
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &QuarantineProcessCapture{Profile: first.Profile, Flags: first.Flags, Agent: bytes.Clone(first.Agent), Metadata: bytes.Clone(first.Metadata), Tracking: bytes.Clone(first.Tracking), Absent: first.Absent}, nil
}
