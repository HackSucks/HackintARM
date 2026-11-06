package appledouble

import "errors"

// ACLUpdate describes copyfile's deferred ACL replacement decision. Apply a
// non-nil ACL after other metadata has been restored; it replaces rather than
// merges with an existing ACL. A valid zero-entry ACL requests clearing entries.
// A nil ACL means preserve the destination ACL. Invalid distinguishes ignored
// malformed text from absent/empty records. RecordIndex is the selected position
// in File.Attrs, or -1 when there is no nonempty ACL record.
//
// This is a policy decision, not a filesystem operation. Destination write
// failures, ownership, file flags and inheritance still require host transport.
type ACLUpdate struct {
	RecordIndex int
	ACL         *ACL
	Invalid     bool
}

// ACLUpdate selects the last nonempty serialized ACL record and parses it once,
// as native copyfile does after restoring other metadata. Malformed ACL text is
// ignored with Invalid=true, preserving the existing destination ACL; it does
// not cause fallback to an earlier record. Missing source identity resolution
// and resolver errors are returned explicitly and must not be treated as a
// successful no-op. A nil File has no ACL update.
func (f *File) ACLUpdate(resolve ACLResolver) (ACLUpdate, error) {
	update := ACLUpdate{RecordIndex: -1}
	if f == nil {
		return update, nil
	}
	for i, a := range f.Attrs {
		if a.Name == ACLTextName && len(a.Value) != 0 {
			update.RecordIndex = i
		}
	}
	if update.RecordIndex < 0 {
		return update, nil
	}
	// Preserve resolver errors even if they wrap ErrACLText: operational lookup
	// failure is distinct from the malformed-policy case native unpack ignores.
	var lookupFailed bool
	var resolver ACLResolver
	if resolve != nil {
		resolver = func(id ACLIdentity) ([16]byte, error) {
			uuid, err := resolve(id)
			lookupFailed = err != nil
			return uuid, err
		}
	}
	acl, err := ParseACLText(f.Attrs[update.RecordIndex].Value, resolver)
	if err != nil {
		if !lookupFailed && errors.Is(err, ErrACLText) {
			update.Invalid = true
			return update, nil
		}
		return update, err
	}
	update.ACL = acl
	return update, nil
}
