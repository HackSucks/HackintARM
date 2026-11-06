package hostdata

import (
	"errors"
	"fmt"
	"io/fs"
)

var (
	// ErrSecuritySourceNotSupported classifies the descriptor statx ENOTSUP
	// fallback condition. Providers should join it with the original read error.
	ErrSecuritySourceNotSupported = errors.New("security source statx not supported")
	// ErrSecuritySourceNotPermitted classifies only statx EPERM, not EACCES or
	// arbitrary permission failures. Providers retain the original cause as well.
	ErrSecuritySourceNotPermitted = errors.New("security source statx not permitted")
	// ErrSecuritySourceType means the captured Darwin file type is neither a
	// regular file, directory nor symlink, matching fcopyfile's source gate.
	ErrSecuritySourceType = errors.New("unsupported security source file type")
)

// SecuritySourceStat contains Darwin stat fields, independently of optional
// filesec properties. Mode includes file type as well as permission bits.
type SecuritySourceStat struct{ UID, GID, Mode uint32 }

// SecuritySourceCapture binds reads to one held source or immutable foreign
// object. ReadSecurity returns the stat and filesec state left by the read,
// including partial state on error. Only the two classified statx errors above
// permit fallback. A plain permission, I/O or missing-file error stays fatal.
//
// ReadStat receives the prior stat state and returns the state left by fstat,
// including on failure. Native fcopyfile historically ignores this error. The
// coordinator retains it and still checks the resulting file type. Neither a
// fallback nor Completed establishes that ACLs were observed or preserved.
//
// Callbacks must not mutate the destination. Capture is not atomic; the
// coordinator does not open host paths or pin handles. Callers must maintain
// source binding and exclude concurrent metadata changes.
// These callbacks and the coordinator work on every OS with native or foreign
// metadata. This models fresh descriptor acquisition, not copyfile's path opener
// or reuse of an already-populated copyfile_state_t.
type SecuritySourceCapture struct {
	ReadSecurity func() (SecurityCopySource, error)
	ReadStat     func(SecuritySourceStat) (SecuritySourceStat, error)
}

// SecuritySourceFailure retains a source read failure, including a failure that
// the native acquisition sequence ignores before proceeding to security copying.
type SecuritySourceFailure struct {
	// Operation is "security" or "stat"; Err retains the original read error.
	Operation string
	Err       error
}

// SecuritySourceResult separates completion of native acquisition from complete
// observation. Source owns the acquired cache. Inspect Failures even on success;
// a fallback can leave omitted or partial filesec properties. Fatal errors never
// authorize destination writes. Source is available for diagnostics on error.
type SecuritySourceResult struct {
	Source              SecurityCopySource
	Completed, Fallback bool
	Failures            []SecuritySourceFailure
}

// CaptureSecuritySource acquires fresh source state using fcopyfile's descriptor
// rules: statx, optional EPERM/ENOTSUP fstat fallback, then the supported-type
// gate. It never promotes stat fallback fields into omitted filesec properties.
// Read errors are preserved; unknown ACL state is not reported as confirmed
// absence. Missing callbacks fail only when needed, before any destination work.
func CaptureSecuritySource(capture SecuritySourceCapture) (result SecuritySourceResult, err error) {
	if capture.ReadSecurity == nil {
		return result, fmt.Errorf("capture source security: %w", fs.ErrInvalid)
	}
	source, readErr := capture.ReadSecurity()
	result.Source, err = cloneSecurityCopySource(source)
	if readErr != nil {
		result.Failures = append(result.Failures, SecuritySourceFailure{Operation: "security", Err: readErr})
	}
	if err != nil {
		return result, fmt.Errorf("validate captured source: %w", err)
	}
	if readErr != nil {
		if !errors.Is(readErr, ErrSecuritySourceNotSupported) && !errors.Is(readErr, ErrSecuritySourceNotPermitted) {
			return result, fmt.Errorf("capture source security: %w", readErr)
		}
		result.Fallback = true
		if capture.ReadStat == nil {
			return result, fmt.Errorf("capture source stat backend: %w", fs.ErrInvalid)
		}
		stat, statErr := capture.ReadStat(SecuritySourceStat{UID: source.UID, GID: source.GID, Mode: source.Mode})
		result.Source.UID, result.Source.GID, result.Source.Mode = stat.UID, stat.GID, stat.Mode
		if statErr != nil {
			result.Failures = append(result.Failures, SecuritySourceFailure{Operation: "stat", Err: statErr})
		}
	}
	switch result.Source.Mode & 0170000 {
	case 0100000, 0040000, 0120000:
		result.Completed = true
		return result, nil
	default:
		return result, ErrSecuritySourceType
	}
}

// SecuritySourceCopyResult retains acquisition diagnostics separately from the
// ordinary copy's query/write diagnostics and resulting ACL-selected cache.
// Capture.Source remains the pre-selection source. Copy.Source may differ.
type SecuritySourceCopyResult struct {
	Capture SecuritySourceResult
	Copy    SecurityCopyResult
}

// CopySecurityFrom acquires a source before the ordinary security stage. With
// neither ACL nor Stat selected it performs no reads, validation or writes.
// Any fatal acquisition error stops before destination capture or volume queries.
// Historical acquisition failures are retained in Capture.Failures; consumers
// requiring fully observed metadata must inspect them as well as Copy.Failures.
func CopySecurityFrom(capture SecuritySourceCapture, options SecurityCopyOptions, backend SecurityCopyBackend) (result SecuritySourceCopyResult, err error) {
	if !options.ACL && !options.Stat {
		result.Copy.Completed = true
		return result, nil
	}
	result.Capture, err = CaptureSecuritySource(capture)
	if err != nil {
		return result, err
	}
	result.Copy, err = CopySecurity(result.Capture.Source, options, backend)
	return result, err
}
