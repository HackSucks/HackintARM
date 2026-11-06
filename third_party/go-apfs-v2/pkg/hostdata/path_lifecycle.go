package hostdata

import (
	"context"
	"errors"
	"fmt"
	"os"

	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

// ErrPathLifecycleUndefined identifies an error path that would restore an
// uninitialized destination stat buffer in the pinned C implementation.
var ErrPathLifecycleUndefined = errors.New("native path lifecycle has uninitialized destination stat")

// ErrPathWorkLimit identifies exhaustion of an explicit open/retry budget.
// Repeated existence/directory responses can prevent endpoint acquisition;
// a bounded operation exposes this limit rather than inventing native errno.
var ErrPathWorkLimit = errors.New("path lifecycle operation budget exhausted")

// PathDestinationState is the observation made before opening either endpoint.
// NoFollowLink denotes an observed final symlink; its filesec is still captured.
type PathDestinationState struct {
	Stat         StatCopySource
	Properties   aclmeta.DarwinChmodProperties
	NoFollowLink bool
}

// PathLifecycleOptions selects the outer path sequence. The bound backend owns
// pack/unpack options and explicit source/destination policy observations.
// MaxOpenAttempts bounds retries independently of native error classification.
type PathLifecycleOptions struct {
	Stat, Exclusive, MoveSource, UnlinkDestination bool
	MaxOpenAttempts                                uint64
}

// PathOpenResult reports partial open effects even when endpoint acquisition
// fails. A backend reports additional permission effects so error-exit
// restoration remains independent of whether endpoint acquisition completed.
type PathOpenResult struct {
	PermissionsChanged bool
	Steps              []HeldLifecycleStep
}

// PathLifecycleBackend binds every effect to one source/destination operation.
// Close must close all owned handles exactly once, including partially opened
// operations, and return every close attempt. It must not use the canceled
// context to omit restoration or release. Caller-owned roots remain open.
//
// Open performs source acquisition, identity/type checks, quarantine capture,
// destination creation/inheritance and the measured open retry sequence. It
// must honor ctx and attempts. Run executes the selected route without applying
// fcopyfile's different held-descriptor outer sequence. A failing pack route
// removes its bound destination before returning, retaining removal diagnostics.
// RestoreBSD attempts ownership then mode even if ownership fails. ResetSecurity
// handles only the first matching temporary ACE and retains native fallbacks.
// The concrete bindings are responsible for actual or captured host operations;
// no callback may represent an unknown observation as successful absence.
type PathLifecycleBackend interface {
	SameObject() (bool, error)
	CaptureDestination() (PathDestinationState, error)
	RealUserUUID() ([16]byte, error)
	ApplyTemporarySecurity(aclmeta.DarwinChmodProperties) error
	Open(context.Context, uint64) (PathOpenResult, error)
	ValidateDestination() error
	CloseTemporarySecurity() []HeldLifecycleStep
	ConfigureIO() []HeldLifecycleStep
	Run(context.Context) (CopyStageResult, []HeldLifecycleStep)
	RestoreBSD(StatCopySource, bool) []HeldLifecycleStep
	ResetSecurity() []HeldLifecycleStep
	RemoveSource() error
	Close() []HeldLifecycleStep
}

// PathLifecycleResult retains native control flow separately from ignored
// errors and actual cleanup. DestinationCreated means the initial destination
// stat returned ENOENT, exactly as in copyfile; it is not a rollback guarantee.
// Steps includes failures even when Code is nonnegative. Close errors do not
// replace a primary failure or the native code, but are joined into Go's error.
type PathLifecycleResult struct {
	Code                                 int
	Completed, DestinationCreated        bool
	PermissionsChanged, DestinationKnown bool
	Steps                                []HeldLifecycleStep
}

// CopyPathMetadata executes the path-based AppleDouble outer lifecycle. It
// retains acquisition, temporary permission, route, reset and close order.
// Cancellation enters the ordinary error cleanup and still releases ownership.
// There is no transaction: existing pack destinations may already be truncated
// or unlinked by a failed route. Temporary permission cleanup uses the retained
// destination descriptor; identity is checked before writing and after opening.
func CopyPathMetadata(ctx context.Context, options PathLifecycleOptions, backend PathLifecycleBackend) (result PathLifecycleResult, err error) {
	result.Code = -1
	if ctx == nil || backend == nil || options.MaxOpenAttempts == 0 {
		return result, os.ErrInvalid
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	defer func() {
		for _, step := range backend.Close() {
			result.Steps = append(result.Steps, step)
			if step.Err != nil {
				err = errors.Join(err, fmt.Errorf("%s: %w", step.Operation, step.Err))
			}
		}
	}()
	record := func(operation string, e error) {
		result.Steps = append(result.Steps, HeldLifecycleStep{Operation: operation, Err: e})
	}
	same, sameErr := backend.SameObject()
	record("same-object", sameErr)
	// Apple's identity probe treats a failed observation as not proven equal.
	if sameErr == nil && same {
		if options.Exclusive {
			return result, os.ErrExist
		}
		result.Code, result.Completed = 0, true
		return result, nil
	}
	original, captureErr := backend.CaptureDestination()
	record("destination-security", captureErr)
	if errors.Is(captureErr, ErrFilesecAllocation) {
		return result, captureErr
	}
	result.DestinationKnown = captureErr == nil
	result.DestinationCreated = errors.Is(captureErr, os.ErrNotExist)
	fail := func(cause error) (PathLifecycleResult, error) {
		if result.PermissionsChanged && !result.DestinationCreated {
			if !result.DestinationKnown {
				cause = errors.Join(cause, ErrPathLifecycleUndefined)
			} else {
				for _, step := range backend.RestoreBSD(original.Stat, true) {
					result.Steps = append(result.Steps, step)
					cause = errors.Join(cause, step.Err)
				}
			}
		}
		for _, step := range backend.CloseTemporarySecurity() {
			result.Steps = append(result.Steps, step)
			cause = errors.Join(cause, step.Err)
		}
		result.Code = -1
		return result, cause
	}
	if captureErr == nil && !options.UnlinkDestination {
		var realUser [16]byte
		var prepareErr error
		if security := original.Properties.RawSecurity; security != nil && security.ACL != nil {
			realUser, prepareErr = backend.RealUserUUID()
			record("real-user", prepareErr)
		}
		if prepareErr == nil {
			var prepared aclmeta.DarwinChmodProperties
			prepared, prepareErr = PreparePathSecurity(original.Properties, realUser)
			record("prepare-security", prepareErr)
			if prepareErr == nil {
				if e := ctx.Err(); e != nil {
					return fail(e)
				}
				e := backend.ApplyTemporarySecurity(prepared)
				record("temporary-security", e)
				if e != nil {
					return fail(e)
				}
				result.PermissionsChanged = true
			}
		}
	}
	if e := ctx.Err(); e != nil {
		return fail(e)
	}
	opened, openErr := backend.Open(ctx, options.MaxOpenAttempts)
	result.PermissionsChanged = result.PermissionsChanged || opened.PermissionsChanged
	result.Steps = append(result.Steps, opened.Steps...)
	record("open", openErr)
	if openErr != nil {
		return fail(openErr)
	}
	if e := ctx.Err(); e != nil {
		return fail(e)
	}
	validationErr := backend.ValidateDestination()
	record("validate-destination", validationErr)
	if validationErr != nil {
		return fail(validationErr)
	}
	result.Steps = append(result.Steps, backend.ConfigureIO()...)
	if e := ctx.Err(); e != nil {
		return fail(e)
	}
	route, routeSteps := backend.Run(ctx)
	result.Code = route.Code
	record("route", route.Err)
	result.Steps = append(result.Steps, routeSteps...)
	if route.Code == -1 {
		cause := route.Err
		if cause == nil {
			cause = errors.New("native path route returned -1")
		}
		for _, step := range routeSteps {
			cause = errors.Join(cause, step.Err)
		}
		return fail(cause)
	}
	if e := ctx.Err(); e != nil {
		return fail(errors.Join(route.Err, e))
	}
	if !options.Stat && !result.DestinationCreated {
		if !result.DestinationKnown {
			return fail(errors.Join(ErrPathLifecycleUndefined, captureErr))
		}
		result.Steps = append(result.Steps, backend.RestoreBSD(original.Stat, false)...)
	}
	for _, step := range backend.CloseTemporarySecurity() {
		result.Steps = append(result.Steps, step)
		err = errors.Join(err, step.Err)
	}
	result.Steps = append(result.Steps, backend.ResetSecurity()...)
	if options.MoveSource {
		record("remove-source", backend.RemoveSource())
	}
	result.Completed = result.Code >= 0
	if result.Code < 0 {
		return result, errors.Join(route.Err, fmt.Errorf("native path route returned %d", result.Code))
	}
	return result, err
}
