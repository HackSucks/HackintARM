package hostdata

import (
	"errors"
	"fmt"
	"os"
)

// CopyStage identifies an operation on the same held source/destination pair.
type CopyStage string

const (
	CopyStagePack       CopyStage = "pack"
	CopyStageUnpack     CopyStage = "unpack"
	CopyStageXattrs     CopyStage = "xattrs"
	CopyStageData       CopyStage = "data"
	CopyStageSecurity   CopyStage = "security"
	CopyStageStat       CopyStage = "stat"
	CopyStageRunInPlace CopyStage = "quarantine-run-in-place"
	CopyStageQuarantine CopyStage = "quarantine"
	CopyStageRemove     CopyStage = "remove-destination"
)

// CopyStageResult keeps a native-style return code separate from diagnostics.
// Negative stage codes stop execution; positive codes can continue and be
// overwritten by a later stage. Quarantine uses nonzero, not negative, as its
// failure condition. Err is retained even when the native sequence ignores it.
// Providers must return a negative Code for a fatal ordinary-stage error.
type CopyStageResult struct {
	Code int
	Err  error
}

// CopyPipelineStep retains each attempted operation and its result, in order.
type CopyPipelineStep struct {
	Stage  CopyStage
	Result CopyStageResult
}

// CopyPipelineBackend operates on already acquired endpoints. Run receives
// only pack/unpack/xattrs/data/security/stat; selection details come from the
// caller's bound options. Pack/unpack own their entire route. In particular,
// unpack applies deferred ACL replacement BEFORE its final stat stage.
// RemoveDestination must remove only the bound destination pathname. Neither
// this interface nor the coordinator authorizes reopening a path or following
// a link. Providers own path safety, partial effects and stage diagnostics.
type CopyPipelineBackend interface {
	Run(CopyStage) CopyStageResult
	RemoveDestination() error
}

// CopyPipelineQuarantine represents captured quarantine state. Nil means
// confirmed absence. AllowRunInPlace reads its flags and writes them with
// QTN_FLAG_DO_NOT_TRANSLOCATE added; the provider owns representation/profile
// conversion. Apply acts on the held destination. Acquisition, flag conversion
// and process authorization are not implemented by this coordinator.
type CopyPipelineQuarantine interface {
	AllowRunInPlace() CopyStageResult
	Apply() CopyStageResult
}

// CopyPipelineAction uses copyfile callback values. Only Quit stops this
// coordinator; Skip, Continue and unknown values all continue after a failed
// quarantine application, as copyfile_internal does.
type CopyPipelineAction int

const (
	CopyPipelineContinue CopyPipelineAction = iota
	CopyPipelineSkip
	CopyPipelineQuit
)

// CopyQuarantineNotice exists only for a failed quarantine Apply call. Xattr is
// the logical attribute name; no mutable callback state survives the call.
type CopyQuarantineNotice struct {
	Xattr  string
	Result CopyStageResult
}

// CopyPipelineOptions selects the inner copyfile routes. Pack takes precedence
// over Unpack; both bypass all ordinary stages. Stat also selects Security.
// Data or SparseData selects a single data stage. These booleans do not claim
// that a provider implements sparse copying or an AppleDouble codec.
type CopyPipelineOptions struct {
	SourceReady, DestinationReady, HasDestinationPath             bool
	Pack, Unpack, Xattrs, Data, SparseData, ACL, Stat, RunInPlace bool
	Quarantine                                                    CopyPipelineQuarantine
	OnQuarantineError                                             func(CopyQuarantineNotice) CopyPipelineAction
}

// CopyPipelineResult reports native control flow, not successful preservation.
// Completed means the final Code is nonnegative. Ignored failures and positive
// results remain in Steps; inspect them and the providers' detailed results.
// Cleanup is recorded without replacing the original failing stage result.
// Ambient errno and the surrounding copyfile_state error cache are not modeled.
type CopyPipelineResult struct {
	Code      int
	Completed bool
	Steps     []CopyPipelineStep
}

// CopyQuarantineError retains a positive quarantine library error code. It is
// not a syscall.Errno: translating it through the current host would change its
// meaning on Linux and Windows.
type CopyQuarantineError int

func (e CopyQuarantineError) Error() string {
	return fmt.Sprintf("quarantine application code %d", int(e))
}

// RunCopyPipeline executes copyfile_internal ordering without opening, creating
// or closing endpoints. Native negative stage codes are preserved except unpack,
// whose negative result becomes -1. Only failed pack/data operations request
// removal, and only with HasDestinationPath. There is no rollback. Callback
// panics are not recovered. Callers must exclude concurrent endpoint mutation.
func RunCopyPipeline(options CopyPipelineOptions, backend CopyPipelineBackend) (result CopyPipelineResult, err error) {
	result.Code = -1
	if !options.SourceReady || !options.DestinationReady || backend == nil {
		return result, fmt.Errorf("copy pipeline endpoints/backend: %w", os.ErrInvalid)
	}
	result.Code = 0
	record := func(stage CopyStage, r CopyStageResult) CopyStageResult {
		result.Steps = append(result.Steps, CopyPipelineStep{Stage: stage, Result: r})
		return r
	}
	stage := func(s CopyStage) bool {
		r := record(s, backend.Run(s))
		result.Code = r.Code
		if r.Code >= 0 {
			return true
		}
		err = r.Err
		if err == nil {
			err = fmt.Errorf("copy stage %s returned %d", s, r.Code)
		}
		if (s == CopyStagePack || s == CopyStageData) && options.HasDestinationPath {
			cleanup := CopyStageResult{Err: backend.RemoveDestination()}
			if cleanup.Err != nil {
				cleanup.Code = -1
			}
			record(CopyStageRemove, cleanup)
		}
		return false
	}
	if options.Pack {
		result.Completed = stage(CopyStagePack)
		return result, err
	}
	if options.Unpack {
		result.Completed = stage(CopyStageUnpack)
		if !result.Completed {
			result.Code = -1
		}
		return result, err
	}
	if q := options.Quarantine; q != nil {
		if options.RunInPlace {
			r := record(CopyStageRunInPlace, q.AllowRunInPlace())
			if r.Code != 0 {
				result.Code = -1
				return result, errors.Join(os.ErrInvalid, r.Err)
			}
		}
		r := record(CopyStageQuarantine, q.Apply())
		if r.Code != 0 && options.OnQuarantineError != nil && options.OnQuarantineError(CopyQuarantineNotice{Xattr: "com.apple.quarantine", Result: r}) == CopyPipelineQuit {
			result.Code = -1
			reason := error(CopyQuarantineError(r.Code))
			if r.Code < 0 {
				reason = errors.ErrUnsupported
			}
			return result, errors.Join(reason, r.Err)
		}
	}
	for _, selected := range []struct {
		stage   CopyStage
		enabled bool
	}{
		{CopyStageXattrs, options.Xattrs},
		{CopyStageData, options.Data || options.SparseData},
		{CopyStageSecurity, options.ACL || options.Stat},
		{CopyStageStat, options.Stat},
	} {
		if selected.enabled && !stage(selected.stage) {
			return result, err
		}
	}
	result.Completed = true
	return result, nil
}
