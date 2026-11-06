package acl

import (
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// ACLMetadata is captured destination security plus numeric ownership and the
// Darwin st_mode bits (not os.FileMode). Zero UID, GID and mode are real values,
// not instructions to omit an update. BSD flags are not part of this request:
// the backend must leave them unchanged and respect filesystem write refusals.
type ACLMetadata struct {
	Security       *appledouble.FileSecurity
	UID, GID, Mode uint32
}

// ACLRestoreBackend binds restoration to a held destination and source context.
// Implementations must keep object identity stable throughout the operation and
// exclude concurrent metadata mutation. No method may silently lose metadata.
// This portable protocol does not itself open paths or provide OS/carrier adapters.
type ACLRestoreBackend interface {
	// CaptureACL reads current destination security, ownership and mode. Failure
	// must be an error, not an empty or absent ACL. Security must be non-nil.
	CaptureACL() (ACLMetadata, error)
	// WriteACL replaces the ACL and retains the supplied ownership/mode. It may
	// retain or mutate its owned request. Actual unsupported-operation errors must
	// wrap errors.ErrUnsupported as well as the original cause; permission and
	// I/O errors must not be classified as unsupported. A write error can leave
	// partial changes; the executor neither rolls back nor assumes atomicity.
	WriteACL(ACLMetadata) error
	// ClearSourceSecurity discards cached source ACL, owner-UUID and group-UUID
	// properties, attempting all three even if one fails. It must NOT clear the
	// destination ACL, change numeric source metadata or modify the write request.
	// Its effect remains even when the subsequent retry fails.
	ClearSourceSecurity() error
}

// ACLRestoreResult records completed work, including when restoration fails.
// Applied is true only after a successful write. Attempts counts WriteACL calls;
// Retried is true only when a second write was actually attempted.
type ACLRestoreResult struct {
	Applied  bool
	Attempts int
	Retried  bool
}

// RestoreACL executes a selected, deferred AppleDouble ACL update after other
// metadata restoration. It captures destination security once, replaces the ACL
// while preserving ownership/mode, and propagates capture/write failures. Absent
// or ignored malformed updates are no-ops and require no backend.
//
// Like copyfile's ACL stage, the first unsupported write clears cached SOURCE
// security and retries the SAME request once. It never clears the destination,
// recaptures metadata, removes restrictive flags or retries other errors. A cache
// reset failure stops the operation and retains both error causes. This is not
// full copyfile lifecycle ordering, an authorization evaluator or a transaction.
// Source callbacks and transport are explicit on every operating system.
func RestoreACL(update appledouble.ACLUpdate, backend ACLRestoreBackend) (result ACLRestoreResult, err error) {
	// Validate and freeze the selected ACL before invoking caller code.
	prepared, err := update.FileSecurity(&appledouble.FileSecurity{})
	if err != nil {
		return result, fmt.Errorf("prepare ACL restoration: %w", err)
	}
	if prepared == nil {
		return result, nil
	}
	if backend == nil {
		return result, fmt.Errorf("ACL restoration backend: %w", os.ErrInvalid)
	}
	destination, err := backend.CaptureACL()
	if err != nil {
		return result, fmt.Errorf("capture destination ACL: %w", err)
	}
	if destination.Security == nil {
		return result, fmt.Errorf("capture destination ACL: %w", appledouble.ErrFileSecurity)
	}
	prepared.OwnerUUID = destination.Security.OwnerUUID
	prepared.GroupUUID = destination.Security.GroupUUID
	destination.Security = prepared
	for {
		result.Attempts++
		result.Retried = result.Attempts == 2
		err = backend.WriteACL(destination.CloneForRestore())
		if err == nil {
			result.Applied = true
			return result, nil
		}
		if result.Attempts == 2 || !errors.Is(err, errors.ErrUnsupported) {
			return result, fmt.Errorf("write destination ACL (attempt %d): %w", result.Attempts, err)
		}
		if resetErr := backend.ClearSourceSecurity(); resetErr != nil {
			return result, fmt.Errorf("clear cached source security after unsupported ACL write: %w", errors.Join(err, resetErr))
		}
	}
}

// CloneForRestore copies metadata with a validated, present replacement ACL.
// Security and Security.ACL must both be non-nil. Each backend invocation owns
// its copy, so mutation cannot alter a retry or the caller's selected ACL.
func (metadata ACLMetadata) CloneForRestore() ACLMetadata {
	security := *metadata.Security
	acl := *security.ACL
	acl.Entries = slices.Clone(acl.Entries)
	security.ACL = &acl
	metadata.Security = &security
	return metadata
}
