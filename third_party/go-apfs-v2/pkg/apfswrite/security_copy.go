package apfswrite

import (
	"os"

	"github.com/deploymenttheory/go-apfs-v2/internal/imageacl"
	"github.com/deploymenttheory/go-apfs-v2/internal/unixmode"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// CopySecurity stages ordinary security copying from an independently captured
// source onto target within root. It merges explicit source and inherited
// destination ACL entries and applies the selected numeric properties and set-ID
// policy. Regular hard-link aliases update together; invalid trees or conflicting
// alias security fail before changes. Targets are pointers; symlinks are not followed.
//
// Completed means staged, not serialized: CreateContainer must still succeed.
// This pure-Go operation performs no host authorization, native fallback or
// timestamp synthesis. BSD flags, payloads and unrelated attributes remain intact.
// Volume policy can be precaptured or queried through options.VolumePolicy.
// Providers must not mutate the tree. Exclude concurrent tree mutation.
// A subsequent deferred RestoreACL replaces the merged ACL.
func (root *Entry) CopySecurity(target *Entry, source hostdata.SecurityCopySource, options hostdata.SecurityCopyOptions) (hostdata.SecurityCopyResult, error) {
	return imageacl.Copy(root, target, source, options, (*Entry).imageSecurityNode, applySecurityCopy)
}

func applySecurityCopy(e *Entry, change imageacl.Change) {
	e.UID, e.GID, e.Xattrs = change.UID, change.GID, change.Xattrs
	if change.ModeSelected {
		e.Mode = e.Mode&^(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) | unixmode.FilePermissions(change.Mode)
		if change.Mode&0170000 == 0040000 {
			e.Mode |= os.ModeDir
		}
		e.ModeExplicit = true
	}
}
