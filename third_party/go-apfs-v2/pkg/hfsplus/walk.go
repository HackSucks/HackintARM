package hfsplus

import (
	"context"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/internal/hostwalk"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/fidelity"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

// WalkOptions tunes EntryTreeFromDir.
type WalkOptions struct {
	// MetadataRoot explicitly selects a separate managed carrier for preservation.
	MetadataRoot   string
	MetadataLimits *metatransport.Limits
	CaptureLimits  *hostdata.XattrCaptureLimits
	Context        context.Context
	// Xattrs reads each entry's extended attributes so they can be counted,
	// and carried when this writer can represent them. It costs a syscall or
	// two per entry, so it is opt-in; without it the report says nothing about
	// attributes rather than saying there were none.
	//
	// A resource fork reaches the walk as an extended attribute even though
	// HFS+ stores it as a fork, so carrying one needs this set.
	Xattrs bool

	// Decompress writes a transparently compressed file out in full instead of
	// carrying its compression across. The default is to carry it: the
	// compressed bytes are what the source held, copying them is cheaper than
	// decompressing, and the result takes less room.
	//
	// Compression can only be carried when Xattrs is set, because that is where
	// a compressed file keeps its content.
	Decompress bool

	// Warn, when non-nil, is called once for each thing the walk cannot carry
	// across, as it is found. The library never writes to stderr itself —
	// deciding whether a warning is worth showing, and how many, belongs to the
	// caller.
	Warn func(path string, kind fidelity.Kind, detail string)
}

// EntryTreeFromDir walks srcDir into an Entry tree and reports everything it
// could not represent. srcDir's own name is dropped; its contents become the
// returned root's children.
//
// The returned Report is never nil. A caller wanting only the tree can ignore
// it, but it is returned rather than hidden because a lossy conversion that
// does not say so is the failure mode this exists to prevent.
//
// Extended attributes are carried, whatever their size: a small value lives
// inside its record in the attributes file and a larger one gets an allocation
// extent of its own. A resource fork is carried too, in the catalog record's
// resource fork where HFS+ actually keeps it. Active compression is preserved
// unless Decompress is selected; inactive compression attributes remain opaque
// metadata beside ordinary data. Several names for one file are written as hard links to
// one copy of the content, rather than as copies.
func EntryTreeFromDir(srcDir string, opts *WalkOptions) (*Entry, *fidelity.Report, error) {
	o := walkOptions(opts)

	root, report, err := hostwalk.Walk(srcDir, &o, newEntry)
	if err != nil {
		return nil, report, err
	}
	return root, report, nil
}

// CanWriteXattr reports whether this writer can carry an extended attribute.
//
// It exists so a caller walking a source tree can tell in advance what will
// survive, rather than discovering it afterwards. It must agree exactly with
// what the writer does: an attribute accepted here and then silently discarded
// would make the fidelity report claim a loss did not happen.
func CanWriteXattr(name string, value []byte) bool {
	// A resource fork is carried, but not through the attributes file -- it is
	// a fork of the catalog record, and newEntry routes it there.
	//
	// com.apple.decmpfs is carried too, and with it UF_COMPRESSED. Whether the
	// file as a whole is consistent -- an empty data fork, a resource fork
	// present exactly when the compression type calls for one -- is a property
	// of the entry rather than of the attribute, so CreateImage checks it. See
	// validateTree.
	return name != "" && !strings.ContainsRune(name, 0)
}

// newEntry builds one HFS+ Entry from the walker's platform-neutral node.
func newEntry(n hostwalk.Node, children []*Entry) *Entry {
	return &Entry{
		Name:              n.Name,
		Mode:              n.Mode,
		ModeExplicit:      n.Name != "" || n.ModeExplicit,
		ModTime:           n.ModTime,
		Times:             n.Times,
		BSDFlags:          n.BSDFlags,
		UID:               n.UID,
		GID:               n.GID,
		Data:              n.Data,
		DataValue:         n.DataValue,
		ResourceFork:      n.Xattrs[hostdata.ResourceForkName],
		ResourceForkValue: n.XattrValues[hostdata.ResourceForkName],
		XattrValues:       valuesWithoutResourceFork(n.XattrValues),
		Xattrs:            attrsWithoutResourceFork(n.Xattrs),
		LinkGroup:         n.LinkGroup,
		Children:          children,
	}
}

// attrsWithoutResourceFork drops the resource fork from the attribute map: it
// reaches a walker as an attribute, but HFS+ stores it as a fork, and writing
// it into the attributes file as well would both duplicate the content and
// disagree with what a reader reports.
func attrsWithoutResourceFork(attrs map[string][]byte) map[string][]byte {
	if _, ok := attrs[hostdata.ResourceForkName]; !ok {
		return attrs
	}
	out := make(map[string][]byte, len(attrs)-1)
	for name, value := range attrs {
		if name != hostdata.ResourceForkName {
			out[name] = value
		}
	}
	return out
}

func walkOptions(opts *WalkOptions) hostwalk.Options {
	var o hostwalk.Options
	if opts != nil {
		o = hostwalk.Options{
			MetadataRoot:   opts.MetadataRoot,
			MetadataLimits: opts.MetadataLimits,
			CaptureLimits:  opts.CaptureLimits,
			Context:        opts.Context,
			Xattrs:         opts.Xattrs,
			Compression:    !opts.Decompress,
			Warn:           opts.Warn,
			Keep:           CanWriteXattr,
			KeepName:       func(name string) bool { return CanWriteXattr(name, nil) },
			HardLinks:      true,
		}
	}

	return o
}

// EntryTree retains borrowed immutable sources until Close. Keep it open through
// image creation; exclude concurrent source edits, including same-size edits.
type EntryTree struct {
	Root   *Entry
	Report *fidelity.Report
	source *hostwalk.Tree[*Entry]
}

// Close invalidates borrowed values and releases held roots. It is idempotent.
func (t *EntryTree) Close() error { return t.source.Close() }

// OpenEntryTreeFromDir walks with bounded-memory file and carrier readers. Native
// attributes still use CaptureLimits. The caller closes the returned tree after
// writing the image. EntryTreeFromDir remains the owned byte-slice alternative.
func OpenEntryTreeFromDir(srcDir string, opts *WalkOptions) (*EntryTree, error) {
	o := walkOptions(opts)
	tree, err := hostwalk.OpenWalk(srcDir, &o, newEntry)
	if err != nil {
		return nil, err
	}
	return &EntryTree{Root: tree.Root, Report: tree.Report, source: tree}, nil
}

func valuesWithoutResourceFork(attrs map[string]appledouble.Value) map[string]appledouble.Value {
	if _, ok := attrs[hostdata.ResourceForkName]; !ok {
		return attrs
	}
	out := make(map[string]appledouble.Value, len(attrs)-1)
	for name, value := range attrs {
		if name != hostdata.ResourceForkName {
			out[name] = value
		}
	}
	return out
}
