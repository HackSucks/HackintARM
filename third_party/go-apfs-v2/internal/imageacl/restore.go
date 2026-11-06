// Package imageacl applies deferred ACL updates to in-memory image trees.
package imageacl

import (
	"bytes"
	"maps"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

// Node is the metadata needed to bind a writer entry and its hard-link aliases.
// Read must report the writer's resolved mode, including its root/default rules.
type Node[T comparable] struct {
	Children  []T
	UID, GID  uint32
	Mode      uint16
	LinkGroup uint64
	Xattrs    map[string][]byte
}

// Restore binds a target by object identity rather than following a host path.
// Read-only validation precedes every edit. The caller excludes concurrent tree
// mutation; write must only assign the supplied map and cannot fail. Matching
// regular-file LinkGroups are updated together. Conflicting security metadata
// across aliases is an error rather than an order-dependent successful write.
func Restore[T comparable](root, target T, update appledouble.ACLUpdate, read func(T, bool) (Node[T], error), write func(T, map[string][]byte)) (aclmeta.ACLRestoreResult, error) {
	if update.ACL == nil || update.Invalid {
		return aclmeta.RestoreACL(update, nil)
	}
	if _, err := update.FileSecurity(&appledouble.FileSecurity{}); err != nil {
		return aclmeta.ACLRestoreResult{}, err
	}
	aliases, nodes, destination, err := bind(root, target, read)
	if err != nil {
		return aclmeta.ACLRestoreResult{}, err
	}
	backend := &restorer{uid: destination.UID, gid: destination.GID, mode: destination.Mode}
	if raw, present := destination.Xattrs[hostdata.SecurityName]; present {
		backend.raw = []byte{} // Present nil/oversized values are invalid, not absent.
		if hostdata.SecurityRecordSizeValid(uint64(len(raw))) {
			backend.raw = bytes.Clone(raw)
		}
	}
	result, err := aclmeta.RestoreACL(update, backend)
	if err != nil || !result.Applied {
		return result, err
	}
	// Allocate every changed map before publishing any update; unrelated values
	// and payloads retain their original storage. Each alias owns its new ACL.
	prepared := make([]map[string][]byte, len(aliases))
	for i, entry := range aliases {
		attrs := maps.Clone(nodes[entry].Xattrs)
		if attrs == nil {
			attrs = map[string][]byte{}
		}
		attrs[hostdata.SecurityName] = bytes.Clone(backend.output)
		prepared[i] = attrs
	}
	for i, entry := range aliases {
		write(entry, prepared[i])
	}
	return result, nil
}

type restorer struct {
	uid, gid    uint32
	mode        uint16
	raw, output []byte
}

func (r *restorer) CaptureACL() (aclmeta.ACLMetadata, error) {
	view := hostdata.DecodeImageSecurity(r.uid, r.gid, r.mode, r.raw)
	security := view.Source.Properties.RawSecurity
	if security == nil {
		security = &appledouble.FileSecurity{}
	}
	return aclmeta.ACLMetadata{UID: r.uid, GID: r.gid, Mode: uint32(r.mode), Security: security}, nil
}

func (r *restorer) WriteACL(m aclmeta.ACLMetadata) error {
	// Extended chmod selects an ACL, not new UUID ownership. Retain the stored
	// UUIDs even when Libc's zero-entry statx view omitted them during capture.
	security := &appledouble.FileSecurity{ACL: m.Security.ACL}
	if hostdata.SecurityRecordSizeValid(uint64(len(r.raw))) {
		if stored, err := appledouble.ParseFileSecurity(r.raw); err == nil {
			security.OwnerUUID, security.GroupUUID = stored.OwnerUUID, stored.GroupUUID
		}
	}
	var err error
	r.output, err = security.MarshalBinary()
	return err
}

// This backend has no cached source security or unsupported-operation fallback.
func (*restorer) ClearSourceSecurity() error { return nil }
