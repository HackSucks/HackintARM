package hostdata

import (
	"errors"
	"fmt"
	"os"
)

// ErrHeldLifecycleUndefined identifies fcopyfile's uninitialized destination
// stat failure path. No guessed permission bits are submitted to a destination.
var ErrHeldLifecycleUndefined = errors.New("native descriptor lifecycle has uninitialized destination stat")

// HeldLifecycleEndpoint is metadata bound to an acquired source or destination.
// Both HeldMetadata and LogicalMetadata implement it. The caller owns endpoint
// lifetimes and excludes concurrent mutation for the complete operation.
type HeldLifecycleEndpoint interface {
	CaptureSecurity() (SecurityCopySource, error)
	CaptureStat() (StatCopySource, error)
	Chmod(uint16) error
	DisableCache() error
}

// HeldLifecycleOptions selects the outer fcopyfile sequence. SourceCache, when
// non-nil, models an already acquired source in a reused native copyfile state;
// it is copied and validated, never read again or changed through this pointer.
type HeldLifecycleOptions struct {
	Stat, NoCache bool
	SourceCache   *SecurityCopySource
}

// HeldLifecycleStages supplies operation-specific quarantine acquisition and
// the selected inner route. Both callbacks are required: confirmed absence is
// an explicit no-op capture, not a missing provider. CaptureQuarantine errors
// are retained and ignored in native order. Run receives owned source state.
// An inner route can be RunCopyPipeline, PackAppleDouble or sequential unpack;
// their detailed result remains owned by the caller's closure.
type HeldLifecycleStages struct {
	CaptureQuarantine func() error
	Run               func(SecurityCopySource) CopyStageResult
}

// HeldLifecycleStep records an attempted operation and its actual error.
type HeldLifecycleStep struct {
	Operation string
	Err       error
}

// HeldLifecycleResult separates native return code from all ignored failures.
// ModeRestored means the reset write succeeded; it is false if STAT selected,
// no reset occurred, or reset failed. A successful code never conceals Steps.
type HeldLifecycleResult struct {
	Code                    int
	Completed, ModeRestored bool
	Capture                 SecuritySourceResult
	Steps                   []HeldLifecycleStep
}

// CopyHeldMetadata executes the complete fresh/reused descriptor fcopyfile
// outer sequence around the caller's selected inner route. It temporarily adds
// owner read/write, captures quarantine, optionally disables caching, runs the
// route and restores the original mode unless STAT was selected. Reset occurs
// even after a failing route, and its error cannot replace the route's code.
//
// This descriptor API neither opens/creates paths, inserts a temporary ACL,
// syncs, nor closes caller-owned handles: native fcopyfile does none of those.
// Path-based copyfile has a distinct lifecycle. A failed destination stat enters
// undefined C behavior; this API stops with ErrHeldLifecycleUndefined before
// permission changes. It retains the original read error as well.
func CopyHeldMetadata(source, destination HeldLifecycleEndpoint, options HeldLifecycleOptions, stages HeldLifecycleStages) (result HeldLifecycleResult, err error) {
	result.Code = -1
	if source == nil || destination == nil || stages.CaptureQuarantine == nil || stages.Run == nil {
		return result, os.ErrInvalid
	}
	var capture SecuritySourceCapture
	if options.SourceCache != nil {
		capture.ReadSecurity = func() (SecurityCopySource, error) { return *options.SourceCache, nil }
	} else {
		capture.ReadSecurity = source.CaptureSecurity
		capture.ReadStat = func(prior SecuritySourceStat) (SecuritySourceStat, error) {
			stat, e := source.CaptureStat()
			if e != nil {
				return prior, e
			}
			return SecuritySourceStat{UID: stat.UID, GID: stat.GID, Mode: stat.Mode}, nil
		}
	}
	result.Capture, err = CaptureSecuritySource(capture)
	if err != nil {
		return result, err
	}
	destinationStat, err := destination.CaptureStat()
	result.step("destination-stat", err)
	if err != nil {
		return result, errors.Join(ErrHeldLifecycleUndefined, err)
	}
	result.step("temporary-mode", destination.Chmod(uint16(destinationStat.Mode&^0170000)|0600))
	result.step("quarantine-capture", stages.CaptureQuarantine())
	if options.NoCache {
		result.step("source-no-cache", source.DisableCache())
		result.step("destination-no-cache", destination.DisableCache())
	}
	stage := stages.Run(result.Capture.Source)
	result.Code = stage.Code
	result.step("route", stage.Err)
	if !options.Stat {
		resetErr := destination.Chmod(uint16(destinationStat.Mode &^ 0170000))
		result.step("reset-mode", resetErr)
		result.ModeRestored = resetErr == nil
	}
	result.Completed = result.Code >= 0
	if result.Code < 0 {
		if stage.Err != nil {
			return result, stage.Err
		}
		return result, fmt.Errorf("native descriptor route returned %d", result.Code)
	}
	return result, nil
}

func (r *HeldLifecycleResult) step(operation string, err error) {
	r.Steps = append(r.Steps, HeldLifecycleStep{Operation: operation, Err: err})
}
