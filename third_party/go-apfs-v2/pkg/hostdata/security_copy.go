package hostdata

import (
	"fmt"
	"os"
	"slices"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

// SecurityCopySource contains independently captured filesec properties and
// stat metadata. Stat values supply fallback writes, even when a filesec
// property is omitted. Mode contains Darwin st_mode bits, not os.FileMode.
type SecurityCopySource struct {
	Properties     aclmeta.DarwinChmodProperties
	UID, GID, Mode uint32
}

// SecurityCopyOptions selects copyfile's security stage and its set-ID policy.
// With VolumePolicy nil, NoSetID means the corresponding volume was positively
// identified as MNT_NOSUID. Volume lookup failures must remain distinguishable
// in the capture layer; they do not establish this capability.
type SecurityCopyOptions struct {
	ACL, Stat                         bool
	AlwaysCopySetID, ForbidCopySetID  bool
	SourceNoSetID, DestinationNoSetID bool
	// VolumePolicy acquires policy lazily in native order. When supplied, both
	// precaptured NoSetID fields must be false. See SecurityCopyVolumePolicy.
	VolumePolicy SecurityCopyVolumePolicy
}

// SecurityCopyBackend binds every operation to the same held destination.
// Callers must exclude concurrent mutation. Nil ACL means confirmed absence,
// not capture failure. Methods own their request storage. Errors can accompany
// partial effects; neither rollback nor atomicity is implied. All platforms
// can implement this protocol using native or foreign-metadata carriers.
type SecurityCopyBackend interface {
	CaptureDestinationACL() (*appledouble.ACL, error)
	WriteSecurity(aclmeta.DarwinChmodArguments) error
	Chmod(uint16) error
	Chown(uid, gid uint32) error
	SetACL(*appledouble.ACL) error
}

// SecurityCopyFailure retains an operation's actual error, including errors
// that native copyfile historically ignores. Operation is "security", "mode",
// "ownership" or "acl". A failed write may already have changed metadata.
type SecurityCopyFailure struct {
	Operation string
	Err       error
}

// SecurityCopyResult distinguishes completion of the native sequence from
// successful preservation. Completed does NOT mean every write succeeded:
// consumers must examine Failures and, when necessary, recapture the target.
// Source owns the resulting source cache, including ACL selection even if later
// writes fail. It is populated only for a selected stage after input validation.
// With neither stage selected, the result is a completed no-op with no snapshot.
// Only this cache changes; the source filesystem is never written.
type SecurityCopyResult struct {
	Source              SecurityCopySource
	Completed, Fallback bool
	Writes              int
	Failures            []SecurityCopyFailure
	// VolumeQueries retains attempted lookups in order, including failures.
	// Failed queries do not count as writes or make Completed false.
	VolumeQueries []SecurityCopyVolumeQuery
}

// CopySecurity executes the ordinary copyfile_security stage. It merges ACLs
// when requested, filters set-ID bits according to captured policy, and submits
// only the requested filesec properties. ACL-only writes omit numeric
// ownership and mode but retain UUID properties. A failed combined write still
// falls back to source stat ownership, even for ACL-only copies, as native
// copyfile does.
//
// Capture/validation/selection errors stop execution and return an error.
// Write errors are retained in result.Failures while the historical native
// sequence continues: optional mode, ownership, then a present ACL. Stat-only
// requests issue just chmod here. No error is reclassified or retried as an
// unsupported operation. This is not AppleDouble's deferred RestoreACL stage,
// a complete copyfile lifecycle, a path opener or an authorization evaluator.
func CopySecurity(source SecurityCopySource, options SecurityCopyOptions, backend SecurityCopyBackend) (result SecurityCopyResult, err error) {
	if !options.ACL && !options.Stat {
		result.Completed = true
		return result, nil
	}
	result.Source, err = cloneSecurityCopySource(source)
	if err != nil {
		return result, fmt.Errorf("prepare security copy: %w", err)
	}
	if backend == nil {
		return result, fmt.Errorf("security copy backend: %w", os.ErrInvalid)
	}
	if options.VolumePolicy != nil && (options.SourceNoSetID || options.DestinationNoSetID) {
		return result, fmt.Errorf("mixed captured and queried volume policy: %w", os.ErrInvalid)
	}
	if options.ACL {
		// Libc cannot materialize FILESEC_ACL from a present NOACL raw record.
		// This differs from an omitted property and fails before destination capture.
		if raw := result.Source.Properties.RawSecurity; raw != nil && raw.ACL == nil {
			return result, fmt.Errorf("capture source ACL: %w", appledouble.ErrFileSecurity)
		}
		destination, captureErr := backend.CaptureDestinationACL()
		if captureErr != nil {
			return result, fmt.Errorf("capture destination ACL: %w", captureErr)
		}
		var original *appledouble.ACL
		if result.Source.Properties.RawSecurity != nil {
			original = result.Source.Properties.RawSecurity.ACL
		}
		selected, selectErr := appledouble.CopyACL(original, destination)
		if selectErr != nil {
			return result, fmt.Errorf("select copied ACL: %w", selectErr)
		}
		if selected != nil {
			result.Source.Properties.RawSecurity = &appledouble.FileSecurity{ACL: selected}
		}
	}
	// Duplicate the cache before filtering so the cache retains the original
	// properties. Every subsequent backend request owns independent storage.
	working, err := cloneSecurityCopySource(result.Source)
	if err != nil {
		return result, err
	}
	properties := working.Properties
	mode := uint16(source.Mode)
	if securityCopyNoSetID(options, &result) {
		mode &^= 06000
		if properties.Mode != nil {
			*properties.Mode &^= 06000
		}
	}
	record := func(operation string, writeErr error) {
		result.Writes++
		if writeErr != nil {
			result.Failures = append(result.Failures, SecurityCopyFailure{Operation: operation, Err: writeErr})
		}
	}
	if !options.ACL {
		record("mode", backend.Chmod(mode))
	} else {
		if !options.Stat {
			properties.UID, properties.GID, properties.Mode = nil, nil, nil
		}
		arguments, requestErr := properties.ChmodArguments()
		if requestErr != nil {
			return result, requestErr
		}
		writeErr := backend.WriteSecurity(arguments)
		record("security", writeErr)
		if writeErr != nil {
			result.Fallback = true
			if options.Stat {
				record("mode", backend.Chmod(mode))
			}
			record("ownership", backend.Chown(source.UID, source.GID))
			if properties.RawSecurity != nil && properties.RawSecurity.ACL != nil {
				record("acl", backend.SetACL(properties.RawSecurity.ACL))
			}
		}
	}
	result.Completed = true
	return result, nil
}

func cloneSecurityCopySource(source SecurityCopySource) (SecurityCopySource, error) {
	// Removal is an operation rather than captured source metadata. Validate all
	// properties before callbacks, including when stat-only execution omits ACLs.
	p := &source.Properties
	if p.RemoveACL {
		return SecurityCopySource{}, appledouble.ErrFileSecurity
	}
	if _, err := p.ChmodArguments(); err != nil {
		return SecurityCopySource{}, err
	}
	for _, field := range []**uint32{&p.UID, &p.GID, &p.Mode} {
		if *field != nil {
			value := **field
			*field = &value
		}
	}
	for _, field := range []**[16]byte{&p.OwnerUUID, &p.GroupUUID} {
		if *field != nil {
			value := **field
			*field = &value
		}
	}
	if p.RawSecurity != nil {
		security := *p.RawSecurity
		if security.ACL != nil {
			acl := *security.ACL
			acl.Entries = slices.Clone(acl.Entries)
			security.ACL = &acl
		}
		p.RawSecurity = &security
	}
	return source, nil
}
