package apfswrite

import (
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
	return imageacl.RestoreXattr(root, target, name, value, options, (*Entry).imageSecurityNode, func(e *Entry, attrs map[string][]byte) { e.Xattrs = attrs })
}
