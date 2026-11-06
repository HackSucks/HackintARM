package hostdata

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// ErrUnpackListAllocation distinguishes refusal to allocate the destination
// name buffer from a failed list read. Native unpack exits after the former
// (with return code zero) but continues after the latter. Providers join their
// allocation/budget error with this sentinel so the diagnostic survives.
var ErrUnpackListAllocation = errors.New("AppleDouble destination name allocation refused")

// UnpackStage distinguishes ATTR records from the two dedicated slots: their
// callback and error rules differ even when their logical xattr names match.
type UnpackStage string

const (
	UnpackOrdinary     UnpackStage = "ordinary"
	UnpackFinderInfo   UnpackStage = "finder-info"
	UnpackResourceFork UnpackStage = "resource-fork"
	UnpackQuarantine   UnpackStage = "quarantine"
)

// UnpackNotice carries the current progress counter. Dedicated slots do not
// reset or increment it. Only ordinary ATTR writes use RestoreXattr progress.
type UnpackNotice struct {
	Stage UnpackStage
	XattrRestoreNotice
}

// UnpackForkState is captured immediately before restoring a nonempty fork.
// Only modification/access times are restored when Stat is not selected.
type UnpackForkState struct {
	Directory bool
	Times     FileTimes
}

// UnpackBackend binds every call to the same held destination. ListXattrSize
// probes the ordinary visible namespace; XattrNames reads that namespace with
// the probed byte capacity. Providers own allocation, validate the returned
// NUL-separated list and preserve its order. Read races/errors must not become
// a silently truncated list. Compression-hidden and security names must follow
// the captured filesystem's visibility, not the current Go host's namespace.
//
// Query errors join ErrXattrUnsupported for Darwin ENOTSUP or
// ErrXattrRestoreNotPermitted for Darwin EPERM only. Removal failures are retained
// and ignored, as in copyfile. WriteXattr receives an owned value. Quarantine
// handles each serialized record; ACL handles only the last nonempty record.
// Those providers compose the existing conversion/application/restoration APIs.
// Stat receives the Finder-invisible decision and owns the existing stat stage.
// Providers must exclude concurrent mutation and must never reopen a pathname.
type UnpackBackend interface {
	ListXattrSize() (int, error)
	XattrNames(capacity int) ([]string, error)
	RemoveXattr(string) error
	WriteXattr(string, []byte) error
	CaptureForkState() (UnpackForkState, error)
	RestoreForkTimes(UnpackForkState) error
	Quarantine([]byte) CopyStageResult
	ACL([]byte) CopyStageResult
	Stat(makeInvisible bool) CopyStageResult
}

// UnpackOptions carries captured ordinary-xattr policy and shared progress.
// Stat selects final stat copying and suppresses the fork's temporary time reset.
type UnpackOptions struct {
	CopyIntent      uint32
	Sandboxed, Stat bool
	InitialCopied   uint64
	Callback        func(UnpackNotice) CopyPipelineAction
}

// UnpackFailure retains an operation's diagnostic even if native control flow
// ignores it or a later ACL/stat result overwrites its return code.
type UnpackFailure struct {
	Operation, Name string
	Err             error
}

// UnpackResult separates the final native-style code from reaching the end.
// Neither Code==0 nor ReachedEnd proves preservation. A failed initial list
// query can return Code==0 without reaching the end; failed fork work can be
// masked by a later successful ACL/stat stage. Always inspect Failures.
type UnpackResult struct {
	Code                      int
	ReachedEnd, MakeInvisible bool
	Copied                    uint64
	Failures                  []UnpackFailure
}

// RestoreAppleDouble executes cleanup, ordered records, FinderInfo, resource
// fork, deferred ACL and final stat on a validated, owned metadata snapshot.
// Decode runs before any destination operation. This deliberately does not
// reproduce partial destruction from late malformed source reads in copyfile;
// streaming reads, allocation failures and the outer lifecycle remain separate.
// The codec's documented input limits apply. No endpoint is opened or closed.
// Applied changes are never rolled back, including on callback cancellation.
func RestoreAppleDouble(data []byte, options UnpackOptions, backend UnpackBackend) (result UnpackResult, err error) {
	result.Copied = options.InitialCopied
	if backend == nil {
		result.Code = -1
		return result, fs.ErrInvalid
	}
	f, err := appledouble.Decode(data)
	if err != nil {
		result.Code = -1
		return result, err
	}
	i := 0
	input := unpackInput{
		next: func() (appledouble.Attr, bool, error) {
			if i == len(f.Attrs) {
				return appledouble.Attr{}, false, nil
			}
			a := f.Attrs[i]
			i++
			return a, true, nil
		},
		finder:       func() ([32]byte, error) { return f.FinderInfo, nil },
		forkSize:     uint64(len(f.ResourceFork)),
		allocateFork: func() ([]byte, error) { return f.ResourceFork, nil },
		readFork:     func([]byte) error { return nil },
	}
	return restoreAppleDouble(input, options, backend)
}

// unpackInput separates source acquisition from the already qualified effect
// order. Snapshot input is prevalidated; sequential input performs each read at
// its native point, including fork allocation before stat and read after stat.
type unpackInput struct {
	next         func() (appledouble.Attr, bool, error)
	finder       func() ([32]byte, error)
	forkSize     uint64
	allocateFork func() ([]byte, error)
	readFork     func([]byte) error
	rawNames     bool
}

func restoreAppleDouble(input unpackInput, options UnpackOptions, backend UnpackBackend) (result UnpackResult, err error) {
	result.Copied = options.InitialCopied
	failure := func(operation, name string, e error) {
		if e != nil {
			result.Failures = append(result.Failures, UnpackFailure{operation, name, e})
		}
	}
	// Native return codes can be overwritten. Do not lose the earlier diagnostic.
	var lastError error
	setResult := func(operation string, r CopyStageResult) {
		result.Code, lastError = r.Code, r.Err
		failure(operation, "", r.Err)
	}
	finish := func() (UnpackResult, error) {
		if result.Code == 0 {
			return result, nil
		}
		if lastError != nil {
			return result, lastError
		}
		return result, fmt.Errorf("AppleDouble restoration returned %d", result.Code)
	}
	size, e := backend.ListXattrSize()
	failure("list-size", "", e)
	if e != nil {
		if !errors.Is(e, ErrXattrUnsupported) && !errors.Is(e, ErrXattrRestoreNotPermitted) {
			return result, nil
		}
	} else if size < 0 {
		result.Code = -1
		return result, fmt.Errorf("negative xattr list size: %w", fs.ErrInvalid)
	} else if size > 0 {
		names, e := backend.XattrNames(size)
		failure("list-names", "", e)
		if errors.Is(e, ErrUnpackListAllocation) {
			return result, nil
		}
		if e == nil {
			for _, name := range names {
				if validXattrName(name) != nil {
					result.Code = -1
					return result, fmt.Errorf("invalid destination xattr name: %w", fs.ErrInvalid)
				}
			}
			for _, name := range names {
				failure("remove", name, backend.RemoveXattr(name))
			}
		}
	}
	var acl []byte
	for {
		a, more, e := input.next()
		if e != nil {
			failure("source-attribute", "", e)
			result.Code, lastError = -1, e
			return finish()
		}
		if !more {
			break
		}
		switch a.Name {
		case appledouble.ACLTextName:
			result.Code, lastError = 0, nil
			if len(a.Value) > 0 {
				acl = a.Value
			}
		case appledouble.QuarantineName:
			r := backend.Quarantine(a.Value)
			setResult("quarantine", r)
			if r.Code != 0 {
				return finish()
			}
		default:
			opts := XattrRestoreOptions{CopyIntent: options.CopyIntent, Sandboxed: options.Sandboxed, InitialCopied: result.Copied}
			if options.Callback != nil {
				opts.Callback = func(n XattrRestoreNotice) CopyPipelineAction {
					return options.Callback(UnpackNotice{UnpackOrdinary, n})
				}
			}
			apply := RestoreXattr
			if input.rawNames {
				// Native unpack validates wire name framing, then delegates name
				// acceptance and special lengths to the actual write operation.
				apply = restoreXattr
			}
			r, e := apply(a.Name, a.Value, opts, backend.WriteXattr)
			result.Copied = r.Copied
			failure("ordinary", a.Name, r.WriteError)
			if e != nil {
				result.Code, lastError = -1, e
				return finish()
			}
			result.Code, lastError = 0, nil
		}
	}
	notify := func(stage UnpackStage, event XattrRestoreEvent, name string, writeError error) CopyPipelineAction {
		return options.Callback(UnpackNotice{stage, XattrRestoreNotice{Event: event, Name: name, Copied: result.Copied, WriteError: writeError}})
	}
	cancel := func() (UnpackResult, error) { result.Code = -1; return result, ErrXattrRestoreCanceled }
	finder, e := input.finder()
	if e != nil {
		failure("source-finder", "", e)
		result.Code, lastError = -1, e
		return finish()
	}
	if finder != [32]byte{} {
		action := CopyPipelineContinue
		if options.Callback != nil {
			action = notify(UnpackFinderInfo, XattrRestoreStart, appledouble.FinderInfoName, nil)
		}
		if action == CopyPipelineQuit {
			return cancel()
		}
		if action != CopyPipelineSkip {
			e := backend.WriteXattr(appledouble.FinderInfoName, bytes.Clone(finder[:]))
			failure("finder-info", appledouble.FinderInfoName, e)
			if e != nil {
				if options.Callback != nil && notify(UnpackFinderInfo, XattrRestoreError, appledouble.FinderInfoName, e) == CopyPipelineQuit {
					return cancel()
				}
				result.Code, lastError = -1, e
				return finish()
			}
			result.Code, lastError = 0, nil
			if options.Callback != nil && notify(UnpackFinderInfo, XattrRestoreFinish, appledouble.FinderInfoName, nil) == CopyPipelineQuit {
				return cancel()
			}
			result.MakeInvisible = binary.BigEndian.Uint16(finder[8:10])&0x4000 != 0
		}
	}
	if input.forkSize > 0 {
		fork, e := input.allocateFork()
		failure("fork-allocation", "", e)
		var state UnpackForkState
		if e == nil {
			state, e = backend.CaptureForkState()
			failure("fork-stat", "", e)
		}
		if e == nil {
			e = input.readFork(fork)
			failure("source-fork", "", e)
		}
		if e != nil {
			result.Code, lastError = -1, e
		} else {
			action := CopyPipelineContinue
			if options.Callback != nil {
				action = notify(UnpackResourceFork, XattrRestoreStart, appledouble.ResourceForkName, nil)
			}
			if action == CopyPipelineQuit {
				return cancel()
			}
			if action != CopyPipelineSkip {
				e = backend.WriteXattr(appledouble.ResourceForkName, bytes.Clone(fork))
				failure("resource-fork", appledouble.ResourceForkName, e)
				result.Code, lastError = 0, nil
				if e != nil {
					if !(state.Directory && bytes.Equal(fork, emptyUnpackResourceFork())) && !(options.Callback != nil && notify(UnpackResourceFork, XattrRestoreError, appledouble.ResourceForkName, e) == CopyPipelineContinue) {
						result.Code, lastError = -1, e
					}
				} else {
					if options.Callback != nil && notify(UnpackResourceFork, XattrRestoreFinish, appledouble.ResourceForkName, nil) == CopyPipelineQuit {
						return cancel()
					}
					if !options.Stat {
						failure("fork-times", "", backend.RestoreForkTimes(state))
					}
				}
			}
		}
	}
	if acl != nil {
		r := backend.ACL(acl)
		setResult("acl", r)
		if r.Code == -1 {
			return finish()
		}
	}
	if options.Stat {
		setResult("stat", backend.Stat(result.MakeInvisible))
	}
	result.ReachedEnd = true
	return finish()
}

// The exact 286-byte empty-directory resource-fork marker in pinned copyfile.c.
// Only a failed write of this entire value on a directory is suppressed.
func emptyUnpackResourceFork() []byte {
	b := make([]byte, 286)
	for _, off := range []int{0, 4, 256, 260} {
		binary.BigEndian.PutUint32(b[off:], 256)
	}
	for _, off := range []int{12, 268} {
		binary.BigEndian.PutUint32(b[off:], 30)
	}
	copy(b[16:128], "This resource fork intentionally left blank   ")
	binary.BigEndian.PutUint16(b[280:], 28)
	binary.BigEndian.PutUint16(b[282:], 30)
	binary.BigEndian.PutUint16(b[284:], 65535)
	return b
}
