package hfsplus

import (
	"io/fs"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/internal/imageacl"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

// RestoreACL stages a deferred AppleDouble replacement on target within root.
// Target is an entry pointer; symlinks are not followed. Matching regular-file
// LinkGroups update together and must agree on ownership, resolved mode and raw
// security. Invalid trees or conflicting aliases fail without changing entries.
// Absent/ignored updates are no-ops, even without a tree.
//
// Only security xattr maps change. Numeric ownership, mode, times, data/resource
// forks and unrelated attributes remain intact. Applied means staged; CreateImage
// must still succeed. No native authorization or host syscall is performed, on
// any OS. Callers must exclude concurrent tree mutation.
func (root *Entry) RestoreACL(target *Entry, update appledouble.ACLUpdate) (aclmeta.ACLRestoreResult, error) {
	return imageacl.Restore(root, target, update, (*Entry).imageSecurityNode, func(e *Entry, attrs map[string][]byte) { e.Xattrs = attrs })
}

func (e *Entry) imageSecurityNode(isRoot bool) (imageacl.Node[*Entry], error) {
	if hostdata.IsSpecial(e.Mode) || (isRoot && e.Mode.Type() != 0 && e.Mode.Type() != os.ModeDir) {
		return imageacl.Node[*Entry]{}, fs.ErrInvalid
	}
	node := &fileNode{entry: e, isDir: isRoot || e.Mode.IsDir(), isSymlink: e.Mode&os.ModeSymlink != 0}
	if !node.isDir && len(e.Children) != 0 {
		return imageacl.Node[*Entry]{}, fs.ErrInvalid
	}
	return imageacl.Node[*Entry]{Children: e.Children, UID: e.UID, GID: e.GID, Mode: hfsFileMode(node), LinkGroup: e.LinkGroup, Xattrs: e.Xattrs}, nil
}
