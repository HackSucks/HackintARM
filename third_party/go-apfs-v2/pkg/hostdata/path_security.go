package hostdata

import (
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

// TemporaryWriteRights is the exact write permission set used by copyfile's
// temporary leading ACE. It is independent of the receiving host's ACL model.
const TemporaryWriteRights uint32 = 1<<2 | 1<<5 | 1<<8 | 1<<10 | 1<<12 | 1<<20

// ErrFilesecAllocation identifies failure to acquire the native filesec object
// before its stat operation. It must retain the underlying allocation error.
// copyfile distinguishes this stage from an ENOMEM returned by statx itself.
var ErrFilesecAllocation = errors.New("native filesec allocation failed")

// PreparePathSecurity copies captured filesec properties and prepares the
// destination permissions used before path-based AppleDouble operations. A
// present ACL gains a leading allow entry for the captured REAL user UUID;
// absent ACLs stay absent. A present mode gains owner read/write. UUID lookup
// and native authorization belong to the caller's captured source context.
// Inputs and returned properties never share mutable storage.
func PreparePathSecurity(properties aclmeta.DarwinChmodProperties, realUser [16]byte) (aclmeta.DarwinChmodProperties, error) {
	owned, err := cloneSecurityCopySource(SecurityCopySource{Properties: properties})
	if err != nil {
		return aclmeta.DarwinChmodProperties{}, err
	}
	p := owned.Properties
	if p.RawSecurity != nil && p.RawSecurity.ACL != nil {
		acl := p.RawSecurity.ACL
		if len(acl.Entries) == 128 {
			return aclmeta.DarwinChmodProperties{}, fmt.Errorf("temporary write ACE exceeds native ACL capacity: %w", appledouble.ErrFileSecurity)
		}
		acl.Entries = append([]appledouble.ACLEntry{{Principal: realUser, Flags: 1, Rights: TemporaryWriteRights}}, acl.Entries...)
	}
	if p.Mode != nil {
		*p.Mode = uint32(uint16(*p.Mode) | 0600)
	}
	return p, nil
}

// PathSecurityResetBackend operates on the acquired destination. CaptureACL
// must distinguish a missing ACL from a capture failure; a missing ACL has
// non-nil Security and nil Security.ACL. Writes preserve the other captured
// filesec properties and use the caller-selected final mode.
type PathSecurityResetBackend interface {
	CaptureACL() (aclmeta.ACLMetadata, error)
	WriteACL(aclmeta.ACLMetadata) error
	Chmod(uint16) error
}

// PathSecurityResetResult retains errors ignored by native reset_security.
// Removed is true only after successful ACL publication; ModeRestored is true
// after that publication or a successful native-style plain-mode fallback.
type PathSecurityResetResult struct {
	Removed, ModeRestored bool
	Steps                 []HeldLifecycleStep
}

// ResetPathSecurity removes only a matching FIRST temporary ACE, identified by
// allow kind, exact rights and the captured EFFECTIVE user UUID. Later matching
// entries and different real/effective principals remain unchanged. Inheritance
// flags do not determine the ACE kind. No ACL restoration occurs on the path
// operation's error exit; this helper belongs to its successful route only.
//
// Unsupported capture or failed ACL publication falls back to plain chmod,
// matching remove_uberace. Other capture failures are retained without writes.
// Every error remains in Steps even if a fallback succeeds. The caller must
// inspect Steps rather than interpret a completed cleanup as full preservation.
func ResetPathSecurity(backend PathSecurityResetBackend, mode uint16, effectiveUser [16]byte) (result PathSecurityResetResult, err error) {
	if backend == nil {
		return result, fmt.Errorf("path security backend: %w", os.ErrInvalid)
	}
	record := func(operation string, e error) {
		result.Steps = append(result.Steps, HeldLifecycleStep{Operation: operation, Err: e})
		err = errors.Join(err, e)
	}
	fallback := func() {
		e := backend.Chmod(mode &^ 0170000)
		record("reset-mode", e)
		result.ModeRestored = e == nil
	}
	metadata, captureErr := backend.CaptureACL()
	record("reset-capture", captureErr)
	if captureErr != nil {
		if errors.Is(captureErr, ErrFilesecAllocation) || errors.Is(captureErr, errors.ErrUnsupported) || errors.Is(captureErr, ErrSecuritySourceNotSupported) {
			fallback()
		}
		return result, err
	}
	if metadata.Security == nil {
		record("reset-security", appledouble.ErrFileSecurity)
		return result, err
	}
	acl := metadata.Security.ACL
	if acl == nil || len(acl.Entries) == 0 {
		return result, nil
	}
	first := acl.Entries[0]
	if first.Flags&0xf != 1 || first.Principal != effectiveUser || first.Rights != TemporaryWriteRights {
		return result, nil
	}
	metadata = metadata.CloneForRestore()
	metadata.Security.ACL.Entries = slices.Clone(acl.Entries[1:])
	metadata.Mode = uint32(mode &^ 0170000)
	writeErr := backend.WriteACL(metadata)
	record("reset-acl", writeErr)
	if writeErr != nil {
		fallback()
	} else {
		result.Removed, result.ModeRestored = true, true
	}
	return result, err
}
