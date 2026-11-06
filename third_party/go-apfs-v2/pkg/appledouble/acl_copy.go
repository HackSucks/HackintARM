package appledouble

import "errors"

// ErrACLCopy identifies an ACL input or selected result exceeding Darwin's
// 128-entry limit. It does not represent an authorization or write failure.
var ErrACLCopy = errors.New("appledouble: ACL copy exceeds 128 entries")

// CopyACL prepares the ACL used by copyfile's ordinary COPYFILE_ACL stage:
// explicit source entries followed by inherited destination entries. Other
// entries are discarded; retained entries keep their order and all bits. Global
// ACL flags are not copied. Inputs are neither retained nor modified.
//
// Nil inputs mean confirmed absence, never a failed read. Both nil yields nil;
// otherwise even a zero-entry result is present. The result limit counts only
// selected entries, unlike InheritACL's creation allocation rule. Source and
// destination inputs must each contain at most 128 entries.
//
// This is pure-Go copy policy on every OS, not a permission evaluator or native
// writer. It does not create inherited entries from a parent, copy numeric/UUID
// ownership, execute copyfile's fallback writes, or implement full copy ordering.
// AppleDouble ACLUpdate restoration replaces the ACL instead of using this merge.
func CopyACL(source, destination *ACL) (*ACL, error) {
	if (source != nil && len(source.Entries) > 128) || (destination != nil && len(destination.Entries) > 128) {
		return nil, ErrACLCopy
	}
	if source == nil && destination == nil {
		return nil, nil
	}
	const inherited = uint32(1 << 4)
	out := &ACL{}
	for i, acl := range []*ACL{source, destination} {
		if acl == nil {
			continue
		}
		for _, entry := range acl.Entries {
			if (entry.Flags&inherited != 0) != (i == 1) {
				continue
			}
			if len(out.Entries) == 128 {
				return nil, ErrACLCopy
			}
			out.Entries = append(out.Entries, entry)
		}
	}
	return out, nil
}
