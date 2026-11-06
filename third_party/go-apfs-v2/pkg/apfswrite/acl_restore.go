package apfswrite

import (
	"io/fs"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/internal/imageacl"
	"github.com/deploymenttheory/go-apfs-v2/internal/unixmode"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

// RestoreACL stages a deferred AppleDouble replacement on target within root.
// Target is an entry pointer, so symlinks are never followed. Regular hard-link
// aliases are updated together and must agree on ownership, resolved mode and
// stored security. Nil/cyclic/repeated tree entries and conflicting aliases fail
// without changes. Absent/ignored updates are no-ops, even without a tree.
//
// Only security xattr maps change; ownership, exact mode, time, payloads and
// unrelated attributes are retained. Applied means staged in the tree, not yet
// written to disk: CreateContainer must still succeed. This pure-Go operation
// does not authorize native filesystem access. Exclude concurrent tree mutation.
func (root *Entry) RestoreACL(target *Entry, update appledouble.ACLUpdate) (aclmeta.ACLRestoreResult, error) {
	return imageacl.Restore(root, target, update, (*Entry).imageSecurityNode, func(e *Entry, attrs map[string][]byte) { e.Xattrs = attrs })
}

func (e *Entry) imageSecurityNode(isRoot bool) (imageacl.Node[*Entry], error) {
	if hostdata.IsSpecial(e.Mode) || (isRoot && e.Mode.Type() != 0 && e.Mode.Type() != os.ModeDir) {
		return imageacl.Node[*Entry]{}, fs.ErrInvalid
	}
	mode := e.resolvedMode()
	if isRoot {
		mode = sIFDIR | unixmode.Permissions(e.Mode, 0755, e.ModeExplicit || e.Mode != 0)
	}
	if mode&0170000 != sIFDIR && len(e.Children) != 0 {
		return imageacl.Node[*Entry]{}, fs.ErrInvalid
	}
	return imageacl.Node[*Entry]{Children: e.Children, UID: e.UID, GID: e.GID, Mode: mode, LinkGroup: e.LinkGroup, Xattrs: e.Xattrs}, nil
}
