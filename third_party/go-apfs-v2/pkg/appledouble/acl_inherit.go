package appledouble

import (
	"errors"
	"fmt"
)

// ErrACLInheritance identifies an ACL that exceeds Darwin's inheritance
// allocation limit. It does not represent a filesystem permission failure.
var ErrACLInheritance = errors.New("appledouble: ACL inheritance exceeds 128 entries")

// InheritACL computes the ACL for creation on a local Darwin filesystem from
// captured parent and optional initial ACLs. It is pure Go on every platform;
// it neither reads host accounts nor applies permissions. A nil parent means
// confirmed absence (or inheritance disabled by the caller), not a read failure.
// Remote filesystems that enforce their own inheritance require their own policy.
//
// Explicit initial entries precede eligible parent entries. Initial inherited
// entries are discarded. Parent entries gain inherited, lose only_inherit, and
// lose propagation flags for files or limit_inherit. Initial no_inherit blocks
// the parent; global flags are not copied into the result. Inputs are not retained.
//
// A nil result means no ACL. A non-nil empty result retains the distinction of
// an explicitly supplied initial ACL, although a filesystem may store it as
// absence. The 128-entry allocation limit counts initial inherited entries before
// discarding them, matching kauth_acl_inherit. This is creation policy: applying
// an AppleDouble ACLUpdate to an existing destination replaces its ACL without
// invoking this function or merging inherited entries.
func InheritACL(initial, parent *ACL, directory bool) (*ACL, error) {
	const (
		inherited        = uint32(1 << 4)
		fileInherit      = uint32(1 << 5)
		directoryInherit = uint32(1 << 6)
		limitInherit     = uint32(1 << 7)
		onlyInherit      = uint32(1 << 8)
		noInherit        = uint32(1 << 17)
	)
	if (initial != nil && len(initial.Entries) > 128) || (parent != nil && len(parent.Entries) > 128) {
		return nil, ErrACLInheritance
	}
	count := 0
	if initial != nil {
		count = len(initial.Entries)
		if initial.Flags&noInherit != 0 {
			parent = nil
		}
	}
	inheritBit := fileInherit
	if directory {
		inheritBit = directoryInherit
	}
	if parent != nil {
		for _, entry := range parent.Entries {
			if entry.Flags&inheritBit != 0 {
				count++
			}
		}
	}
	if count > 128 {
		return nil, fmt.Errorf("%w: allocation requires %d", ErrACLInheritance, count)
	}
	if count == 0 && initial == nil {
		return nil, nil
	}
	result := &ACL{Entries: make([]ACLEntry, 0, count)}
	if initial != nil {
		for _, entry := range initial.Entries {
			if entry.Flags&inherited == 0 {
				result.Entries = append(result.Entries, entry)
			}
		}
	}
	if parent != nil {
		for _, entry := range parent.Entries {
			if entry.Flags&inheritBit == 0 {
				continue
			}
			entry.Flags = (entry.Flags | inherited) &^ onlyInherit
			if !directory || entry.Flags&limitInherit != 0 {
				entry.Flags &^= fileInherit | directoryInherit | limitInherit | onlyInherit
			}
			result.Entries = append(result.Entries, entry)
		}
	}
	return result, nil
}
