package hostdata

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

var (
	// ErrXattrRestoreNotPermitted classifies Darwin EPERM only, not EACCES.
	// Providers join it with the original write error. It suppresses failure only
	// for the exact com.apple.root.installed name in the ordinary unpack stage.
	ErrXattrRestoreNotPermitted = errors.New("xattr restoration not permitted")
	// ErrXattrRestoreCanceled means a start/finish callback requested termination.
	// An error callback's Quit instead retains the actual write failure.
	ErrXattrRestoreCanceled = errors.New("xattr restoration canceled")
)

// XattrRestoreEvent identifies a callback position within one ordinary record.
type XattrRestoreEvent string

const (
	XattrRestoreStart  XattrRestoreEvent = "start"
	XattrRestoreError  XattrRestoreEvent = "error"
	XattrRestoreFinish XattrRestoreEvent = "finish"
)

// XattrRestoreNotice is an immutable callback snapshot. Copied is copyfile's
// progress counter, not proof that bytes were preserved. A suppressed EPERM on
// com.apple.root.installed still produces Finish with the value's length.
type XattrRestoreNotice struct {
	Event      XattrRestoreEvent
	Name       string
	Copied     uint64
	WriteError error
}

// XattrRestoreOptions supplies already captured process policy, never the
// running Go host's sandbox status. At zero CopyIntent, #N/#n suffix policy and
// the sandboxed com.apple.security. default apply. Any nonzero CopyIntent
// bypasses filtering in Apple's unpack function, including unknown values.
// InitialCopied permits chaining records without losing native progress state.
// Callback values use CopyPipelineAction, but their stage semantics differ:
// Start Skip still writes; Error Continue/Skip/unknown swallow a write error;
// only Quit terminates. Callbacks must not mutate source or destination state.
type XattrRestoreOptions struct {
	CopyIntent    uint32
	Sandboxed     bool
	InitialCopied uint64
	Callback      func(XattrRestoreNotice) CopyPipelineAction
}

// XattrRestoreResult separates control-flow completion from preservation.
// Applied becomes true after a successful write, even if Finish then cancels.
// WriteError survives both callback suppression and the root-installed exception.
// A filtered record has Selected=false and performs no callback or write.
type XattrRestoreResult struct {
	Selected, Completed, Applied bool
	Copied                       uint64
	WriteError                   error
}

// RestoreXattr executes the ordinary copyfile_unpack_xattr stage on a held
// destination. write receives an owned value; nil means a zero-length assignment.
// Ordinary values must retain presence; special attributes can have native
// normalization (for example, an empty resource fork disappears). The writer must
// bind stable identity and preserve logical names/values or return an error.
// The executor never opens a path or supplies a host carrier.
//
// ACL text and serialized quarantine require their dedicated unpack routes and
// are rejected here. FinderInfo/resource-fork ATTR records can use this stage;
// their separate AppleDouble slots have different callbacks and are not covered.
// There is no rollback, destination cleanup, retry or whole-unpack sequencing.
func RestoreXattr(name string, value []byte, options XattrRestoreOptions, write func(string, []byte) error) (result XattrRestoreResult, err error) {
	result.Copied = options.InitialCopied
	if validXattrName(name) != nil || name == appledouble.ACLTextName || name == appledouble.QuarantineName || uint64(len(value)) > uint64(^uint32(0)) {
		return result, fmt.Errorf("ordinary xattr restoration input: %w", os.ErrInvalid)
	}
	return restoreXattr(name, value, options, write)
}

// restoreXattr executes already framed records. Sequential native unpack also
// routes empty/invalid-UTF8 names here: the held provider supplies the actual
// write refusal after Start, instead of changing native callback/error order.
func restoreXattr(name string, value []byte, options XattrRestoreOptions, write func(string, []byte) error) (result XattrRestoreResult, err error) {
	result.Copied = options.InitialCopied
	if !unpackXattrSelected(name, options) {
		result.Completed = true
		return result, nil
	}
	result.Selected = true
	if write == nil {
		return result, fmt.Errorf("xattr restoration writer: %w", os.ErrInvalid)
	}
	// Freeze before Start: later callbacks cannot change the request indirectly.
	prepared := bytes.Clone(value)
	notify := func(event XattrRestoreEvent) CopyPipelineAction {
		return options.Callback(XattrRestoreNotice{Event: event, Name: name, Copied: result.Copied, WriteError: result.WriteError})
	}
	if options.Callback != nil {
		result.Copied = 0
		if notify(XattrRestoreStart) == CopyPipelineQuit {
			return result, ErrXattrRestoreCanceled
		}
	}
	result.WriteError = write(name, prepared)
	result.Applied = result.WriteError == nil
	suppressed := name == "com.apple.root.installed" && errors.Is(result.WriteError, ErrXattrRestoreNotPermitted)
	if result.WriteError != nil && !suppressed {
		if options.Callback == nil || notify(XattrRestoreError) == CopyPipelineQuit {
			return result, result.WriteError
		}
	} else if options.Callback != nil {
		result.Copied = uint64(len(value))
		if notify(XattrRestoreFinish) == CopyPipelineQuit {
			return result, ErrXattrRestoreCanceled
		}
	}
	result.Completed = true
	return result, nil
}

func unpackXattrSelected(name string, options XattrRestoreOptions) bool {
	if options.CopyIntent != 0 {
		return true
	}
	if i := strings.LastIndexByte(name, '#'); i >= 0 {
		never := false
		for _, b := range []byte(name[i+1:]) {
			switch b {
			case 'N':
				never = true
			case 'n':
				never = false
			}
		}
		return !never
	}
	// Only the sandboxed security prefix has default NEVER_PRESERVE in the
	// pinned property tables. Other flags do not exclude unknown/zero intent.
	return !options.Sandboxed || !strings.HasPrefix(name, "com.apple.security.")
}
