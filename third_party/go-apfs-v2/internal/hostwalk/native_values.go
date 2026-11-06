package hostwalk

import (
	"path/filepath"

	"github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/fidelity"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func (w *walker[E]) collectValueXattrs(rel string, active bool) (kept map[string]appledouble.Value, compressed bool, err error) {
	if !w.opts.Xattrs {
		return nil, false, nil
	}
	limits := hostdata.XattrCaptureLimits{NameBytes: hostdata.MaxXattrListSize, ValueBytes: 64 << 20, TotalBytes: 256 << 20}
	if w.opts.CaptureLimits != nil {
		limits = *w.opts.CaptureLimits
	}
	attrs, err := w.opts.nativeValues(w.opts.owner.ctx, w.opts.owner.root, filepath.FromSlash(rel), limits)
	if err != nil {
		return nil, false, err
	}
	accepts := func(name string) bool { return w.opts.KeepName != nil && w.opts.KeepName(name) }
	if value, present := attrs[hostdata.DecmpfsName]; present && active {
		forkBacked, e := decmpfs.UsesResourceFork(value)
		if e != nil {
			return nil, false, e
		}
		compressed = w.opts.Compression && accepts(hostdata.DecmpfsName) && (!forkBacked || accepts(hostdata.ResourceForkName))
		if !compressed {
			delete(attrs, hostdata.DecmpfsName)
			if forkBacked {
				delete(attrs, hostdata.ResourceForkName)
			}
		}
	}
	kept = make(map[string]appledouble.Value, len(attrs))
	for name, value := range attrs {
		if accepts(name) {
			kept[name] = value
			continue
		}
		switch {
		case name == hostdata.ResourceForkName:
			w.warn(rel, fidelity.ResourceFork, name)
		case hostdata.IsACLName(name):
			w.warn(rel, fidelity.ACL, name)
		default:
			w.warn(rel, fidelity.Xattr, name)
		}
	}
	return kept, compressed, nil
}
