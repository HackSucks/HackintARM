package hfsplus

import (
	"io/fs"
	"maps"

	"github.com/deploymenttheory/go-apfs-v2/internal/imageacl"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// RestoreXattr applies one ordinary AppleDouble ATTR record to target and all
// regular hard-link aliases. The complete tree is validated and aliases must
// agree on all xattrs before callbacks run. Target pointers never follow links.
// Applied means published in the tree, including if a later Finish callback
// cancels. Every alias owns the new value/map; unselected metadata remains intact.
// Resource-fork assignments use the existing fork storage; empty assignment clears it.
// The writer must still serialize successfully. This is offline staging, not
// native authorization, kernel normalization or a complete unpack lifecycle.
// Exclude tree mutation during execution, including from callbacks.
func (root *Entry) RestoreXattr(target *Entry, name string, value []byte, options hostdata.XattrRestoreOptions) (hostdata.XattrRestoreResult, error) {
	return imageacl.RestoreXattr(root, target, name, value, options, (*Entry).imageXattrNode, func(e *Entry, attrs map[string][]byte) {
		e.ResourceFork = attrs[hostdata.ResourceForkName]
		delete(attrs, hostdata.ResourceForkName)
		e.Xattrs = attrs
	})
}

// Expose the catalog fork as logical metadata for common alias validation.
func (e *Entry) imageXattrNode(root bool) (imageacl.Node[*Entry], error) {
	n, err := e.imageSecurityNode(root)
	if err != nil {
		return n, err
	}
	if _, wrong := n.Xattrs[hostdata.ResourceForkName]; wrong {
		return n, fs.ErrInvalid
	}
	if len(e.ResourceFork) > 0 {
		n.Xattrs = maps.Clone(n.Xattrs)
		if n.Xattrs == nil {
			n.Xattrs = map[string][]byte{}
		}
		n.Xattrs[hostdata.ResourceForkName] = e.ResourceFork
	}
	return n, nil
}
