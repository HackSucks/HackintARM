package hostwalk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/fidelity"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

// walkCarrier is explicitly selected; arbitrary payload files, including ._
// names, are always content. The caller excludes concurrent tree mutation.
func walkCarrier[E any](dir string, opts *Options, mk func(Node, []E) E) (E, *fidelity.Report, error) {
	return walkCarrierUsing(dir, opts, mk, hostdata.CaptureXattrsNoFollow)
}

type carrierTree interface {
	Lstat(string) (os.FileInfo, error)
	Readlink(string) (string, error)
	ReadFile(string) ([]byte, error)
	FS() fs.FS
	Close() error
}

func walkCarrierUsing[E any](dir string, opts *Options, mk func(Node, []E) E, captureAttrs func(context.Context, string, hostdata.XattrCaptureLimits) (map[string][]byte, error)) (E, *fidelity.Report, error) {
	return walkCarrierBound(dir, opts, mk, captureAttrs, func(p string) (carrierTree, error) { return os.OpenRoot(p) })
}
func walkCarrierBound[E any](dir string, opts *Options, mk func(Node, []E) E, captureAttrs func(context.Context, string, hostdata.XattrCaptureLimits) (map[string][]byte, error), openRoot func(string) (carrierTree, error)) (out E, report *fidelity.Report, err error) {

	report = &fidelity.Report{}
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}
	limits := metatransport.DefaultLimits()
	if opts.MetadataLimits != nil {
		limits = *opts.MetadataLimits
	}
	capture := hostdata.XattrCaptureLimits{NameBytes: hostdata.MaxXattrListSize, ValueBytes: 64 << 20, TotalBytes: 256 << 20}
	if opts.CaptureLimits != nil {
		capture = *opts.CaptureLimits
	}
	store, e := metatransport.Open(dir, opts.MetadataRoot, limits)
	if e != nil {
		return out, report, e
	}
	if opts.owner != nil {
		opts.owner.closers = append(opts.owner.closers, store)
	} else {
		defer func() { err = errors.Join(err, store.Close()) }()
	}
	manifest, e := store.Load(ctx)
	if e != nil {
		return out, report, e
	}
	root, e := openRoot(dir)
	if e != nil {
		return out, report, e
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	records := make(map[string]metatransport.Record, len(manifest.Records))
	seen := map[string]bool{}
	for _, r := range manifest.Records {
		records[r.Materialized] = r
	}
	groups := map[string]uint64{}
	groupNodes := map[string]Node{}
	nextGroup := uint64(1)
	var visit func(string, string) (E, error)
	visit = func(rel, logicalParent string) (zero E, err error) {
		if e := ctx.Err(); e != nil {
			return zero, e
		}
		info, e := root.Lstat(rel)
		if e != nil {
			return zero, e
		}
		if hostdata.IsSpecial(info.Mode()) {
			return zero, fmt.Errorf("carrier payload %q is special: %w", rel, metatransport.ErrConflict)
		}
		node := Node{Name: path.Base(rel), Mode: info.Mode(), ModeExplicit: true, ModTime: info.ModTime()}
		if rel == "." {
			node.Name = ""
		}
		record, recorded := records[rel]
		logical := path.Join(logicalParent, node.Name)
		if recorded {
			seen[rel] = true
			logical = record.Original
			if rel != "." && path.Dir(logical) != logicalParent {
				return zero, fmt.Errorf("metadata parent mapping %q: %w", rel, metatransport.ErrConflict)
			}
			if rel != "." {
				node.Name = path.Base(logical)
			}
			if e = applyCarrierState(&node, record); e != nil {
				return zero, e
			}
			materialized := "file"
			if info.IsDir() {
				materialized = "directory"
			}
			if info.Mode()&os.ModeSymlink != 0 {
				materialized = "symlink"
			}
			if record.MaterializedKind != materialized {
				return zero, metatransport.ErrConflict
			}
			if record.Kind == "symlink" {
				if e = store.VerifyPayload(ctx, record); e != nil {
					return zero, e
				}
			}
		}
		// Capture the host namespace separately. Unsupported native namespaces can
		// still carry complete logical metadata via this explicit carrier.
		var native map[string][]byte
		var nativeValues map[string]appledouble.Value
		if opts.owner != nil && opts.nativeValues != nil {
			nativeValues, e = opts.nativeValues(ctx, opts.owner.root, filepath.FromSlash(rel), capture)
		} else {
			native, e = captureAttrs(ctx, filepath.Join(dir, filepath.FromSlash(rel)), capture)
		}
		if errors.Is(e, hostdata.ErrXattrUnsupported) {
			native = map[string][]byte{}
		} else if e != nil {
			return zero, e
		}
		if opts.owner != nil {
			if recorded {
				node.XattrValues, e = store.BorrowRecordAttributes(ctx, record)
				if e != nil {
					return zero, e
				}
			}
			var baseline map[string]appledouble.Value
			if recorded && (record.NativeCaptured || record.NativeUnsupported) {
				baseline, e = store.BorrowAttributes(ctx, record.NativeAttributes)
				if e != nil {
					return zero, e
				}
			}
			if nativeValues == nil {
				nativeValues = map[string]appledouble.Value{}
				for name, value := range native {
					nativeValues[name] = bytes.NewReader(value)
				}
			}
			node.XattrValues, e = metatransport.ReconcileValues(ctx, nativeValues, baseline, node.XattrValues)
			if e != nil {
				return zero, e
			}
			for name := range node.XattrValues {
				if opts.KeepName != nil && !opts.KeepName(name) {
					return zero, fmt.Errorf("writer cannot preserve %q: %w", name, metatransport.ErrInvalid)
				}
			}
		} else {
			var carried map[string][]byte
			if recorded {
				carried, e = store.ReadRecordAttributes(ctx, record, int64(capture.TotalBytes))
				if e != nil {
					return zero, e
				}
			}
			if recorded && (record.NativeCaptured || record.NativeUnsupported) {
				baseline, readErr := store.ReadNativeBaseline(ctx, record, int64(capture.TotalBytes))
				if readErr != nil {
					return zero, readErr
				}
				node.Xattrs, e = metatransport.ReconcileAttributes(native, baseline, carried)
			} else {
				node.Xattrs, e = metatransport.MergeAttributes(native, carried)
			}

			if e != nil {
				return zero, e
			}
			total := 0
			for name, value := range node.Xattrs {
				if len(value) > capture.ValueBytes || len(value) > capture.TotalBytes-total {
					return zero, metatransport.ErrLimit
				}
				total += len(value)
				if opts.Keep != nil && !opts.Keep(name, value) {
					return zero, fmt.Errorf("writer cannot preserve %q: %w", name, metatransport.ErrInvalid)
				}
			}
		}
		var children []E
		switch {
		case node.Mode&os.ModeSymlink != 0:
			if recorded {
				node.Data = []byte(record.Target)
			} else {
				target, e := root.Readlink(rel)
				if e != nil {
					return zero, e
				}
				node.Data = []byte(target)
			}
		case node.Mode.IsDir():
			entries, e := fs.ReadDir(root.FS(), rel)
			if e != nil {
				return zero, e
			}
			names := map[string]bool{}
			for _, entry := range entries {
				childRel := path.Join(rel, entry.Name())
				childName := entry.Name()
				if r, ok := records[childRel]; ok {
					childName = path.Base(r.Original)
				}
				if names[childName] {
					return zero, metatransport.ErrConflict
				}
				names[childName] = true
				child, e := visit(childRel, logical)
				if e != nil {
					return zero, e
				}
				children = append(children, child)
			}
		default:
			_, compressed := node.Xattrs[hostdata.DecmpfsName]
			if _, ok := node.XattrValues[hostdata.DecmpfsName]; ok {
				compressed = true
			}
			if node.BSDFlags != nil {
				compressed = compressed && *node.BSDFlags&hostdata.UFCompressed != 0
			}
			if compressed && opts.Compression {
				if recorded {
					if e = store.VerifyPayload(ctx, record); e != nil {
						return zero, e
					}
				}
				node.Data = nil
			} else {
				if compressed {
					value := node.XattrValues[hostdata.DecmpfsName]
					if value == nil {
						value = bytes.NewReader(node.Xattrs[hostdata.DecmpfsName])
					}
					forkBacked, shapeErr := decmpfs.UsesResourceFork(value)
					if shapeErr != nil {
						return zero, shapeErr
					}
					delete(node.Xattrs, hostdata.DecmpfsName)
					delete(node.XattrValues, hostdata.DecmpfsName)
					if forkBacked {
						delete(node.Xattrs, hostdata.ResourceForkName)
						delete(node.XattrValues, hostdata.ResourceForkName)
					}
					if node.BSDFlags != nil {
						flags := *node.BSDFlags &^ hostdata.UFCompressed
						node.BSDFlags = &flags
					}
					report.Add(fidelity.Compression, logical)
					if opts.Warn != nil {
						opts.Warn(logical, fidelity.Compression, "decompressed data requested")
					}
				}
				if opts.owner != nil {
					node.DataValue, e = store.BorrowPayload(ctx, rel)
				} else {
					node.Data, e = root.ReadFile(rel)
				}
				if e != nil {
					return zero, e
				}
			}
		}
		if recorded && record.LinkGroup != "" {
			if !opts.HardLinks {
				return zero, fmt.Errorf("writer cannot preserve hard links: %w", metatransport.ErrInvalid)
			}
			group := groups[record.LinkGroup]
			if group == 0 {
				group = nextGroup
				nextGroup++
				groups[record.LinkGroup] = group
				groupNodes[record.LinkGroup] = node
			} else {
				old := groupNodes[record.LinkGroup]
				equal, compareErr := nodesEqual(old, node)
				if compareErr != nil {
					return zero, compareErr
				}
				if !equal {
					return zero, fmt.Errorf("hard-link group %q differs: %w", record.LinkGroup, metatransport.ErrConflict)
				}
			}
			node.LinkGroup = group
		}
		return mk(node, children), nil
	}
	out, e = visit(".", ".")
	if e != nil {
		return out, report, e
	}
	if len(seen) != len(records) {
		return out, report, fmt.Errorf("orphan metadata records: %w", metatransport.ErrConflict)
	}
	return out, report, nil
}

func applyCarrierState(node *Node, r metatransport.Record) error {
	allTimes := r.Darwin.Birth != nil && r.Darwin.Modify != nil && r.Darwin.Change != nil && r.Darwin.Access != nil
	if !allTimes && (r.Darwin.Birth != nil || r.Darwin.Change != nil || r.Darwin.Access != nil) {
		return fmt.Errorf("partial independent inode times: %w", metatransport.ErrInvalid)
	}
	switch r.Kind {
	case "file":
		node.Mode &^= os.ModeType
	case "directory":
		node.Mode = (node.Mode &^ os.ModeType) | os.ModeDir
	case "symlink":
		node.Mode = (node.Mode &^ os.ModeType) | os.ModeSymlink
	}
	if r.Darwin.Mode != nil {
		mode := *r.Darwin.Mode
		if mode&^uint32(0177777) != 0 {
			return metatransport.ErrInvalid
		}
		expected := uint32(0100000)
		if r.Kind == "directory" {
			expected = 0040000
		} else if r.Kind == "symlink" {
			expected = 0120000
		}
		if mode&0170000 != 0 && mode&0170000 != expected {
			return metatransport.ErrConflict
		}
		node.Mode = node.Mode.Type() | os.FileMode(mode&0777)
		if mode&04000 != 0 {
			node.Mode |= os.ModeSetuid
		}
		if mode&02000 != 0 {
			node.Mode |= os.ModeSetgid
		}
		if mode&01000 != 0 {
			node.Mode |= os.ModeSticky
		}
	}
	if r.Darwin.UID != nil {
		node.UID = *r.Darwin.UID
	}
	if r.Darwin.GID != nil {
		node.GID = *r.Darwin.GID
	}
	if r.Darwin.Flags != nil {
		flags := *r.Darwin.Flags
		node.BSDFlags = &flags
	}
	if r.Darwin.Modify != nil {
		node.ModTime = *r.Darwin.Modify
	}
	if allTimes {
		node.Times = &hostdata.FileTimes{Birth: *r.Darwin.Birth, Modify: *r.Darwin.Modify, Change: *r.Darwin.Change, Access: *r.Darwin.Access}
	}
	return nil
}
