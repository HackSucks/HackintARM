package imageacl

import (
	"bytes"
	"fmt"
	"io/fs"
	"maps"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// RestoreXattr binds ordinary unpack writes to a validated image tree. The
// successful write publishes before Finish, so cancellation cannot pretend to
// roll it back. The caller excludes tree mutation during callbacks.
func RestoreXattr[T comparable](root, target T, name string, value []byte, options hostdata.XattrRestoreOptions, read func(T, bool) (Node[T], error), write func(T, map[string][]byte)) (hostdata.XattrRestoreResult, error) {
	aliases, nodes, destination, err := bind(root, target, read)
	if err != nil {
		return hostdata.XattrRestoreResult{}, err
	}
	for _, entry := range aliases {
		if !maps.EqualFunc(destination.Xattrs, nodes[entry].Xattrs, bytes.Equal) {
			return hostdata.XattrRestoreResult{}, fmt.Errorf("conflicting hard-link attributes: %w", fs.ErrInvalid)
		}
	}
	return hostdata.RestoreXattr(name, value, options, func(name string, value []byte) error {
		// Raw security has a separate validated restoration API. Ordinary Darwin
		// fsetxattr cannot be used as an extended-security writer either.
		if name == hostdata.SecurityName {
			return fs.ErrPermission
		}
		if name == hostdata.ResourceForkName && destination.Mode&0170000 != 0100000 {
			return fs.ErrInvalid
		}
		if name == appledouble.FinderInfoName && len(value) != 32 {
			return fs.ErrInvalid
		}
		prepared := make([]map[string][]byte, len(aliases))
		for i, entry := range aliases {
			attrs := maps.Clone(nodes[entry].Xattrs)
			if attrs == nil {
				attrs = map[string][]byte{}
			}
			if name == hostdata.ResourceForkName && len(value) == 0 {
				delete(attrs, name)
			} else {
				attrs[name] = bytes.Clone(value)
			}
			prepared[i] = attrs
		}
		for i, entry := range aliases {
			write(entry, prepared[i])
		}
		return nil
	})
}
