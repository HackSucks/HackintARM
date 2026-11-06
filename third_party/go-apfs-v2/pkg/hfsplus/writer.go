// HFS+ / HFSX volume writer: serialises an in-memory directory tree into a
// raw, mountable HFSX volume image (bytes).
//
// By default it produces a case-sensitive HFSX volume (signature "HX",
// version 5, catalog keyCompareType 0xBC / kHFSBinaryCompare), unjournaled,
// where catalog ordering is a plain lexicographic compare of the big-endian
// UTF-16 name code units. CreateOptions.CaseInsensitive instead produces plain
// HFS+ ("H+", version 4, keyCompareType 0xCF), whose catalog is ordered
// through the fold table in casefold_table.go.
//
// Files carry their data fork, their resource fork and their extended
// attributes; the attributes file is emitted only when something needs it, so a
// volume with no attributes is byte-identical to one this writer produced
// before it could emit one.
//
// All multi-byte on-disk fields are big-endian. Reuses the on-disk structs
// from types.go for serialisation.
package hfsplus

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"sort"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// Entry is one node of the directory tree to be written. A directory has
// Children; a regular file or symlink carries its bytes in Data (for a
// symlink, Data is the target path).
type Entry struct {
	// DataValue, ResourceForkValue and XattrValues borrow immutable sized sources.
	// Keep their owner open until CreateImage completes.
	DataValue         appledouble.Value
	ResourceForkValue appledouble.Value
	XattrValues       map[string]appledouble.Value
	Name              string
	Mode              os.FileMode // type, permissions and Go set-ID/sticky bits
	// ModeExplicit disables default permissions, including on the root.
	// Use true to preserve 0000; false retains the legacy 0644/0755 defaults.
	// Hard-link groups use the first entry's inode metadata.
	ModeExplicit bool
	ModTime      time.Time
	// Times overrides ModTime for all four inode times. Nil keeps legacy
	// defaults; HFS stores whole seconds in its 1904–2040 range. Only Modify
	// is clamped by ClampModTimes. Explicit out-of-range values fail.
	Times *hostdata.FileTimes
	// BSDFlags selects owner/admin catalog flags plus Finder invisibility.
	// Nil retains legacy compression inference. UF_COMPRESSED requires valid
	// decmpfs storage; an explicit clear flag preserves inactive attributes
	// and ordinary data. Unrepresentable bits fail before output writes. The
	// first hard-link entry supplies the shared inode flags; stubs stay internal.
	BSDFlags *uint32
	UID, GID uint32
	Data     []byte   // file content, or symlink target bytes
	Children []*Entry // directory children (writer sorts them)

	// Open supplies a regular file's content lazily. It is the alternative to
	// Data for content too large to hold in memory; setting both is an error.
	//
	// The writer calls it once, while the image is written, closes what it
	// returns, and never retains more than one copy buffer, so a tree of any
	// size costs a fixed amount of memory for content. A file of Size zero is
	// never opened. A symlink's target stays in Data.
	Open func() (io.ReadCloser, error)

	// Size is the length of the content Open yields. The volume is laid out
	// before any content is read, so it is fixed here rather than discovered:
	// content of any other length fails the write.
	Size int64

	// ResourceFork is the file's resource fork, empty when it has none. On
	// HFS+ this is a fork of the catalog record rather than an extended
	// attribute, even though macOS presents it as com.apple.ResourceFork.
	ResourceFork []byte

	// Xattrs are the entry's extended attributes. Directories may carry them
	// too. com.apple.ResourceFork does not belong here -- it is a fork, and
	// goes in ResourceFork above.
	Xattrs map[string][]byte

	// LinkGroup marks entries that are several names for one file. Every name
	// sharing a value is written as a hard link to a single copy of the
	// content; zero means the entry has only one name. The value itself is
	// arbitrary and does not reach the disk.
	LinkGroup uint64
}

// dataLen is the length of the entry's data fork, wherever its bytes come from.
func (e *Entry) dataLen() int {
	if e.Open != nil {
		return int(e.Size)
	}
	return len(e.Data)
}

// CreateOptions tunes image creation. The zero value is valid.
type CreateOptions struct {
	// BlockSize is the allocation block size in bytes (default 4096). Must be
	// a power of two >= 512.
	BlockSize uint32
	// FixedTime is the timestamp written to the volume header's create, modify
	// and checked dates, and the default for entries that carry no ModTime. The
	// zero value selects DefaultTime, so an image is byte-identical for
	// identical input without the caller doing anything.
	FixedTime time.Time
	// ClampModTimes applies the SOURCE_DATE_EPOCH rule to entry modification
	// times: an Entry.ModTime later than the resolved FixedTime is written as
	// FixedTime, while earlier times are preserved. It has no effect on entries
	// that supply no ModTime.
	ClampModTimes bool
	// CaseInsensitive selects a case-insensitive HFS+ volume (signature "H+",
	// version 4, catalog keyCompareType 0xCF) instead of the case-sensitive
	// HFSX default. Names then compare through the fold table in
	// casefold_table.go, which is what macOS itself does.
	CaseInsensitive bool

	// VolumeUUID pins the volume's identifier. Only its first eight bytes reach
	// disk, because the HFS+ volume identifier is the 64-bit pair
	// FinderInfo[6]/FinderInfo[7]. The zero value derives a stable identifier
	// from the volume name and the resolved timestamp.
	VolumeUUID [16]byte
}

// DefaultTime is the timestamp used when CreateOptions.FixedTime is unset. It is
// a fixed value rather than the wall clock so that identical input produces
// identical bytes: an image built twice is byte-for-byte the same.
var DefaultTime = time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)

// internal per-node bookkeeping built from the Entry tree.
type fileNode struct {
	times     [4]hfsTime
	entry     *Entry
	name      string
	cnid      CatalogNodeID
	parent    CatalogNodeID
	isDir     bool
	isSymlink bool
	children  []*fileNode

	dataLen    int
	dataBlocks uint32
	dataStart  uint32 // first allocation block of the data fork

	rsrcLen    int
	rsrcBlocks uint32
	rsrcStart  uint32 // first allocation block of the resource fork

	// attrs are the node's extended attributes, sorted by name. A value too
	// large to sit inside its record gets an extent of its own.
	attrs    []*attrWrite
	bsdFlags uint32

	// isLink marks a visible name pointing at an indirect node; linkRef is
	// that node's catalog id. isINode marks the indirect node itself, which
	// holds the content, and linkCount is how many names refer to it.
	isLink    bool
	linkRef   uint32
	isINode   bool
	linkCount uint32

	// The names for one indirect node form a doubly-linked chain, which is
	// what tells macOS these are modern hard links rather than the pre-Leopard
	// form. On a link record prevLink and nextLink are the neighbouring names'
	// catalog ids, stored where an ordinary record keeps its owner and group;
	// on the indirect node firstLink is the head of that chain, stored in the
	// record's reserved1 field. Zero terminates.
	prevLink  uint32
	nextLink  uint32
	firstLink uint32
}

// attrWrite is one extended attribute to be written.
type attrWrite struct {
	name   string
	value  []byte
	source appledouble.Value
	size   int
	inline bool
	blocks uint32
	start  uint32
}

// layout describes where each metadata region and file data lives, in
// allocation blocks.
type layout struct {
	blockSize    int
	totalBlocks  uint32
	bitmapStart  uint32
	bitmapBlocks uint32
	extentsStart uint32
	extentBlocks uint32
	catalogStart uint32
	catalogBlks  uint32
	attrStart    uint32 // attributes B-tree (zero blocks when there are none)
	attrBlks     uint32
	dataStart    uint32 // first file-data block
	firstFree    uint32 // first free block after all data
}

// CreateImage writes a raw HFSX volume image built from root into w. When
// sizeBytes is 0 a minimum size that fits all metadata and data is computed;
// otherwise sizeBytes (rounded down to a whole number of blocks) is used and
// must be large enough. volumeName becomes the root folder's catalog name.
func CreateImage(w io.WriterAt, sizeBytes int64, volumeName string, root *Entry, opts *CreateOptions) error {
	blockSize := 4096
	var o CreateOptions
	if opts != nil {
		o = *opts
		if o.BlockSize != 0 {
			blockSize = int(o.BlockSize)
		}
	}
	if blockSize < 512 || blockSize&(blockSize-1) != 0 {
		return fmt.Errorf("hfsplus: invalid block size %d", blockSize)
	}
	if root == nil {
		root = &Entry{}
	}
	if err := validateRootSources(root); err != nil {
		return err
	}
	if err := validateCreationNames(root, !o.CaseInsensitive); err != nil {
		return err
	}
	var prepareErr error
	root, prepareErr = prepareValueTree(root, blockSize)
	if prepareErr != nil {
		return prepareErr
	}
	if err := validateTree(root); err != nil {
		return err
	}
	defaultTime := o.FixedTime
	if defaultTime.IsZero() {
		defaultTime = DefaultTime
	}

	// 1. Flatten the tree, assign CNIDs, count files/folders.
	b := &builder{
		caseInsensitive: o.CaseInsensitive,
		blockSize:       blockSize,
		defaultTime:     defaultTime,
		clampTime:       o.ClampModTimes,
		volumeUUID:      o.VolumeUUID,
		nextCNID:        HFSFirstUserCatalogNodeID,
	}
	rootNode := b.flatten(root, volumeName)

	// 1b. Turn groups of names sharing an inode into hard links, which adds
	// the private directory and one indirect node per group.
	b.buildHardLinks()
	if err := b.prepareBSDFlags(); err != nil {
		return err
	}
	if err := b.prepareTimes(); err != nil {
		return err
	}

	// 2. Determine node counts. Both are independent of the fork values the
	// records will eventually carry -- only the record count and sizes matter,
	// and those are already fixed -- so counting now and rebuilding later with
	// real extents cannot change the answer. Step 5 asserts exactly that.
	keyCompare := HFSBinaryCompare
	if o.CaseInsensitive {
		keyCompare = HFSCaseFolding
	}
	tree0 := buildBTree(blockSize, b.catalogRecords(rootNode), keyCompare, 0x00000006, 516, 0)
	catalogBlks := tree0.totalNodes

	var attrBlks uint32
	if b.attrCount > 0 {
		attrBlks = buildBTree(blockSize, b.attrRecords(), 0, attrTreeAttributes, attrMaxKeyLength, 0).totalNodes
	}

	// 3. Compute the layout (and total size).
	lay, err := b.computeLayout(sizeBytes, catalogBlks, attrBlks)
	if err != nil {
		return err
	}

	// 4. Assign each file's data extent now that dataStart is known.
	b.assignData(&lay)

	// 5. Build the final catalog and (empty) extents-overflow B-trees.
	catTree := buildBTree(blockSize, b.catalogRecords(rootNode), keyCompare, 0x00000006, 516, 0)
	if catTree.totalNodes != catalogBlks {
		// Should never happen: node count is independent of fork values.
		return fmt.Errorf("hfsplus: catalog node count changed (%d -> %d)", catalogBlks, catTree.totalNodes)
	}
	extTree := buildBTree(blockSize, nil, 0, 0x00000002, 10, 0)

	// A volume with no attributes gets no attributes file at all, rather than
	// an empty one-node tree: that keeps every image this writer produced
	// before byte-identical, so nothing downstream churns on a feature it does
	// not use.
	var attrTree builtTree
	if b.attrCount > 0 {
		attrTree = buildBTree(blockSize, b.attrRecords(), 0, attrTreeAttributes, attrMaxKeyLength, 0)
		if attrTree.totalNodes != attrBlks {
			return fmt.Errorf("hfsplus: attributes node count changed (%d -> %d)", attrBlks, attrTree.totalNodes)
		}
	}

	// 6. Write the image out region by region, rather than assembling it in
	// memory first. Regions no region covers stay zero: on a file, unwritten
	// ranges read as zeros, exactly as they did in the buffer this replaced.
	total := int64(lay.totalBlocks) * int64(blockSize)

	blockAt := func(block uint32) int64 { return int64(block) * int64(blockSize) }

	// Catalog nodes.
	for i, n := range catTree.nodes {
		if _, err := w.WriteAt(n, blockAt(lay.catalogStart+uint32(i))); err != nil {
			return fmt.Errorf("hfsplus: writing catalog node %d: %w", i, err)
		}
	}
	// Extents-overflow nodes.
	for i, n := range extTree.nodes {
		if _, err := w.WriteAt(n, blockAt(lay.extentsStart+uint32(i))); err != nil {
			return fmt.Errorf("hfsplus: writing extents node %d: %w", i, err)
		}
	}
	// Attributes nodes.
	for i, n := range attrTree.nodes {
		if _, err := w.WriteAt(n, blockAt(lay.attrStart+uint32(i))); err != nil {
			return fmt.Errorf("hfsplus: writing attributes node %d: %w", i, err)
		}
	}
	// File data.
	if err := b.writeFileData(w); err != nil {
		return err
	}

	// 7. Allocation bitmap.
	if _, err := w.WriteAt(b.buildBitmap(&lay), blockAt(lay.bitmapStart)); err != nil {
		return fmt.Errorf("hfsplus: writing allocation bitmap: %w", err)
	}

	// 8. Volume header (primary at 1024, alternate at end-1024).
	vh := b.volumeHeader(volumeName, &lay, catTree, extTree)
	vhBytes := marshalBE(&vh)
	if _, err := w.WriteAt(vhBytes, 1024); err != nil {
		return fmt.Errorf("hfsplus: writing volume header: %w", err)
	}
	if _, err := w.WriteAt(vhBytes, total-1024); err != nil {
		return fmt.Errorf("hfsplus: writing alternate volume header: %w", err)
	}

	// The alternate volume header is 512 bytes and sits at total-1024, so it
	// does not reach the end. Write the final byte so the image is its full
	// declared size however the destination sizes itself.
	if _, err := w.WriteAt([]byte{0}, total-1); err != nil {
		return fmt.Errorf("hfsplus: sizing image: %w", err)
	}
	return nil
}

// CreateImageFromDir walks srcDir into an Entry tree and writes an HFS+ image
// built from it. srcDir's own name is not used; its contents become the volume
// root's children.
//
// The conversion is lossy: device nodes, FIFOs and sockets are skipped, and
// extended attributes, resource forks, ACLs, BSD flags and hard links are not
// carried across. This function discards the account of what was lost; call
// EntryTreeFromDir directly to see it.
func CreateImageFromDir(w io.WriterAt, sizeBytes int64, volumeName, srcDir string, opts *CreateOptions) error {
	root, _, err := EntryTreeFromDir(srcDir, nil)
	if err != nil {
		return err
	}
	return CreateImage(w, sizeBytes, volumeName, root, opts)
}

// builder holds writer state across the layout/build passes.
type builder struct {
	caseInsensitive bool
	blockSize       int
	defaultTime     time.Time
	clampTime       bool
	volumeUUID      [16]byte
	nextCNID        CatalogNodeID

	root      *fileNode
	allNodes  []*fileNode // every node including root
	fileNodes []*fileNode // files and symlinks (have data forks)

	// privateDirTime is the creation date of the private metadata directory,
	// which every hard-link record must repeat; see normalRecord.
	privateDirTime hfsTime

	fileCount   uint32
	folderCount uint32 // excludes the root folder
	attrCount   uint32 // total extended attributes across every node
}

// flatten converts the Entry tree into fileNodes, assigning CNIDs depth-first
// with children sorted by name for determinism.
func (b *builder) flatten(rootEntry *Entry, volumeName string) *fileNode {
	root := &fileNode{
		entry: rootEntry,
		// HFS+ stores names decomposed. Normalizing here rather than at each
		// use means the catalog records, the thread records and the key
		// ordering all agree, and a reader looking for the decomposed form
		// finds what it expects.
		name:   normalizeName(volumeName),
		cnid:   HFSRootFolderID,
		parent: HFSRootParentID,
		isDir:  true,
	}
	b.root = root
	b.allNodes = append(b.allNodes, root)
	// The root folder can carry attributes like any other directory, and it is
	// built here rather than in addChildren, so it needs collecting here too.
	b.collectAttrs(root)
	b.addChildren(root, rootEntry.Children)
	return root
}

func (b *builder) addChildren(parent *fileNode, children []*Entry) {
	sorted := append([]*Entry(nil), children...)
	sort.Slice(sorted, func(i, j int) bool {
		return normalizeName(catalogName(sorted[i].Name)) < normalizeName(catalogName(sorted[j].Name))
	})
	for _, ce := range sorted {
		n := &fileNode{
			entry: ce,
			// Entry.Name is a POSIX name, stored the way HFS+ spells it.
			name:   normalizeName(catalogName(ce.Name)),
			cnid:   b.nextCNID,
			parent: parent.cnid,
		}
		b.nextCNID++
		switch {
		case ce.Mode&os.ModeSymlink != 0:
			n.isSymlink = true
			n.dataLen = ce.dataLen()
			b.fileCount++
			b.fileNodes = append(b.fileNodes, n)
		case ce.Mode.IsDir():
			n.isDir = true
			b.folderCount++
		default:
			n.dataLen = ce.dataLen()
			b.fileCount++
			b.fileNodes = append(b.fileNodes, n)
		}
		if n.dataLen > 0 {
			n.dataBlocks = uint32((n.dataLen + b.blockSize - 1) / b.blockSize)
		}
		// A directory has no forks, and a symlink's target is its data fork;
		// neither carries a resource fork.
		if !n.isDir && !n.isSymlink {
			n.rsrcLen = resourceSize(ce)
			if n.rsrcLen > 0 {
				n.rsrcBlocks = uint32((n.rsrcLen + b.blockSize - 1) / b.blockSize)
			}
		}
		b.collectAttrs(n)
		parent.children = append(parent.children, n)
		b.allNodes = append(b.allNodes, n)
		if n.isDir {
			b.addChildren(n, ce.Children)
		}
	}
}

// collectAttrs turns a node's Entry.Xattrs into the writer's own list, sorted
// by name so the image is byte-identical for identical input, and decides which
// values fit inside their record.
func (b *builder) collectAttrs(n *fileNode) {
	if len(n.entry.Xattrs) == 0 && len(n.entry.XattrValues) == 0 {
		return
	}
	names := make([]string, 0, len(n.entry.Xattrs))
	for name := range n.entry.Xattrs {
		if name == finderInfoName {
			continue
		}
		names = append(names, name)
	}
	for name := range n.entry.XattrValues {
		names = append(names, name)
	}
	sort.Strings(names)

	limit := maxInlineAttrSize(b.blockSize)
	for _, name := range names {
		value := n.entry.Xattrs[name]
		size := len(value)
		source := n.entry.XattrValues[name]
		if source != nil {
			size = int(source.Size())
		}
		a := &attrWrite{name: name, value: value, source: source, size: size, inline: size <= limit}
		if !a.inline {
			a.blocks = uint32((size + b.blockSize - 1) / b.blockSize)
		}
		n.attrs = append(n.attrs, a)
		b.attrCount++
	}
}

// attrRecords builds every attributes-file leaf record, in key order.
func (b *builder) attrRecords() []btRecord {
	if b.attrCount == 0 {
		return nil
	}
	recs := make([]btRecord, 0, b.attrCount)
	for _, n := range b.allNodes {
		for _, a := range n.attrs {
			key := encodeAttrKey(n.cnid, a.name, 0)
			if a.inline {
				recs = append(recs, btRecord{key: key, payload: attrInlineRecord(a.value)})
				continue
			}
			recs = append(recs, btRecord{
				key:     key,
				payload: attrForkRecord(forkDescriptor(a.size, a.blocks, a.start)),
			})
		}
	}
	sort.Slice(recs, func(i, j int) bool { return compareAttrKeys(recs[i].key, recs[j].key) < 0 })
	return recs
}

// computeLayout places metadata and file data in allocation blocks and
// determines the total block count.
func (b *builder) computeLayout(sizeBytes int64, catalogBlks, attrBlks uint32) (layout, error) {
	bs := b.blockSize
	var totalData uint64
	for _, f := range b.fileNodes {
		totalData += uint64(f.dataBlocks) + uint64(f.rsrcBlocks)
	}
	for _, n := range b.allNodes {
		for _, a := range n.attrs {
			totalData += uint64(a.blocks)
		}
	}
	// Bound allocation arithmetic before narrowing on-disk block numbers.
	if err := validateLayoutBlocks(totalData, catalogBlks, attrBlks, bs, sizeBytes); err != nil {
		return layout{}, err
	}

	// Metadata before data: block 0, bitmap, extents (1 node), catalog.
	// Data follows; the last block holds the alternate volume header.
	place := func(total uint32) layout {
		bitmapBytes := (uint64(total) + 7) / 8
		bitmapBlks := uint32((bitmapBytes + uint64(bs) - 1) / uint64(bs))
		lay := layout{blockSize: bs, totalBlocks: total}
		next := uint32(1) // block 0 reserved
		lay.bitmapStart, lay.bitmapBlocks = next, bitmapBlks
		next += bitmapBlks
		lay.extentsStart, lay.extentBlocks = next, 1
		next++
		lay.catalogStart, lay.catalogBlks = next, catalogBlks
		next += catalogBlks
		lay.attrStart, lay.attrBlks = next, attrBlks
		next += attrBlks
		lay.dataStart = next
		next += uint32(totalData)
		lay.firstFree = next
		return lay
	}

	var total uint32
	if sizeBytes > 0 {
		total = uint32(sizeBytes / int64(bs))
	} else {
		// Iterate to a stable total (bitmap size depends on total). Add two
		// trailing blocks so at least one free block and the alternate VH fit.
		total = 8
		for i := 0; i < 8; i++ {
			lay := place(total)
			want := lay.firstFree + 2
			if want <= total {
				break
			}
			total = want
		}
	}

	lay := place(total)
	if lay.firstFree > total-1 { // data must not overlap the alternate-VH block
		return layout{}, fmt.Errorf("hfsplus: image too small: need %d blocks, have %d", lay.firstFree+1, total)
	}
	if total < 4 {
		return layout{}, fmt.Errorf("hfsplus: image too small: %d blocks", total)
	}
	return lay, nil
}

// assignData assigns each file contiguous extents starting at dataStart: its
// data fork, then its resource fork if it has one.
func (b *builder) assignData(lay *layout) {
	next := lay.dataStart
	for _, f := range b.fileNodes {
		if f.dataBlocks > 0 {
			f.dataStart = next
			next += f.dataBlocks
		}
		if f.rsrcBlocks > 0 {
			f.rsrcStart = next
			next += f.rsrcBlocks
		}
	}
	// Attribute values too large to sit inside their record get extents of
	// their own, after the file forks.
	for _, n := range b.allNodes {
		for _, a := range n.attrs {
			if a.blocks > 0 {
				a.start = next
				next += a.blocks
			}
		}
	}
}

// writeFileData copies every file's bytes into the image at its data extent.
func (b *builder) writeFileData(w io.WriterAt) error {
	var buf []byte
	for _, f := range b.fileNodes {
		if f.dataLen > 0 {
			off := int64(f.dataStart) * int64(b.blockSize)
			if f.entry.Open != nil {
				if buf == nil {
					buf = make([]byte, contentBufferSize)
				}
				if err := copyContent(w, off, f.entry, buf); err != nil {
					return fmt.Errorf("hfsplus: writing %s: %w", f.name, err)
				}
			} else if _, err := w.WriteAt(f.entry.Data, off); err != nil {
				return fmt.Errorf("hfsplus: writing %s: %w", f.name, err)
			}
		}
		if f.rsrcLen > 0 {
			off := int64(f.rsrcStart) * int64(b.blockSize)
			var err error
			if f.entry.ResourceForkValue != nil {
				err = writeValue(w, off, f.entry.ResourceForkValue, f.rsrcLen)
			} else {
				_, err = w.WriteAt(f.entry.ResourceFork, off)
			}
			if err != nil {
				return fmt.Errorf("hfsplus: writing resource fork of %s: %w", f.name, err)
			}
		}
	}
	for _, n := range b.allNodes {
		for _, a := range n.attrs {
			if a.blocks == 0 {
				continue
			}
			off := int64(a.start) * int64(b.blockSize)
			var err error
			if a.source != nil {
				err = writeValue(w, off, a.source, a.size)
			} else {
				_, err = w.WriteAt(a.value, off)
			}
			if err != nil {
				return fmt.Errorf("hfsplus: writing attribute %s of %s: %w", a.name, n.name, err)
			}
		}
	}
	return nil
}

// contentBufferSize is the most lazily supplied content held at once.
const contentBufferSize = 1 << 20

// copyContent streams an entry's lazily supplied content into its extent.
//
// The extent was sized from Entry.Size before anything was read, so content of
// any other length is an error rather than something to accommodate: a shorter
// file would leave the fork describing bytes that are not there, and a longer
// one would run into the blocks of the file after it. Nothing past Size is ever
// written, whatever the source goes on to yield.
func copyContent(w io.WriterAt, off int64, e *Entry, buf []byte) (err error) {
	r, err := e.Open()
	if err != nil {
		return err
	}
	defer func() {
		if cerr := r.Close(); err == nil {
			err = cerr
		}
	}()

	n, err := io.CopyBuffer(io.NewOffsetWriter(w, off), io.LimitReader(r, e.Size), buf)
	if err != nil {
		return err
	}
	if n != e.Size {
		return fmt.Errorf("content ended after %d bytes, short of the %d its Size declares", n, e.Size)
	}
	var extra [1]byte
	if m, _ := io.ReadFull(r, extra[:]); m > 0 {
		return fmt.Errorf("content continues past the %d bytes its Size declares", e.Size)
	}
	return nil
}

// forkFor returns the data-fork descriptor for a file node.
func (b *builder) forkFor(f *fileNode) ForkData {
	return forkDescriptor(f.dataLen, f.dataBlocks, f.dataStart)
}

// rsrcForkFor returns the resource-fork descriptor for a file node. It is the
// zero value when the file has no resource fork, which is what fsck_hfs expects
// of a file that does not carry one.
func (b *builder) rsrcForkFor(f *fileNode) ForkData {
	return forkDescriptor(f.rsrcLen, f.rsrcBlocks, f.rsrcStart)
}

func forkDescriptor(length int, blocks, start uint32) ForkData {
	if blocks == 0 {
		return ForkData{}
	}
	fork := ForkData{
		LogicalSize: uint64(length),
		ClumpSize:   65536,
		TotalBlocks: blocks,
	}
	fork.Extents[0] = ExtentDescriptor{StartBlock: start, BlockCount: blocks}
	return fork
}

// catalogRecords builds every catalog leaf record (folder/file + thread for
// each node), sorted in HFSX binary key order.
func (b *builder) catalogRecords(_ *fileNode) []btRecord {
	var recs []btRecord
	for _, n := range b.allNodes {
		recs = append(recs, b.normalRecord(n), b.threadRecord(n))
	}
	cmp := compareCatalogKeys
	if b.caseInsensitive {
		cmp = compareCatalogKeysFolded
	}
	sort.Slice(recs, func(i, j int) bool { return cmp(recs[i].key, recs[j].key) < 0 })
	return recs
}

// nodeTime resolves a node's catalog timestamp. A node with no ModTime takes
// the builder's fixed default; otherwise its own time is used, clamped down to
// that default when ClampModTimes is set (the SOURCE_DATE_EPOCH rule).
func (b *builder) nodeTime(n *fileNode) hfsTime {
	t := n.entry.ModTime
	if t.IsZero() {
		t = b.defaultTime
	} else if b.clampTime && t.After(b.defaultTime) {
		t = b.defaultTime
	}
	return toHFSTime(t)
}

// normalRecord builds the folder or file record keyed by (parent, name).
func (b *builder) normalRecord(n *fileNode) btRecord {
	key := encodeCatalogKey(n.parent, n.name)
	ht := n.times
	bsd := BSDInfo{
		OwnerID:    n.entry.UID,
		GroupID:    n.entry.GID,
		FileMode:   hfsFileMode(n),
		OwnerFlags: uint8(n.bsdFlags),
		AdminFlags: uint8(n.bsdFlags >> 16),
	}

	if n.isDir {
		var subFolders uint32
		for _, c := range n.children {
			if c.isDir {
				subFolders++
			}
		}
		if n.isPrivateDir() {
			// Written the way macOS writes it: invisible and name-locked, an
			// off-screen Finder location, and a mode with no permission bits.
			folder := HFSPlusCatalogFolder{
				RecordType:       HFSPlusFolderRecord,
				Flags:            HFSHasFolderCountMask,
				Valence:          uint32(len(n.children)),
				FolderID:         n.cnid,
				CreateDate:       ht[0],
				ContentModDate:   ht[1],
				AttributeModDate: ht[2],
				AccessDate:       ht[3],
				BSDInfo:          BSDInfo{FileMode: sIFDIR},
				FolderCount:      subFolders,
			}
			folder.UserInfo.FinderFlags = privateDirFinderFlags
			folder.UserInfo.Location.V = privateDirLocation
			folder.UserInfo.Location.H = privateDirLocation
			return btRecord{key: key, payload: marshalBE(&folder)}
		}
		// Directories must NOT set kHFSThreadExistsMask/kHFSFileLockedMask;
		// fsck_hfs treats those bits as reserved-must-be-zero on folders
		// (E_CatalogFlagsNotZero). The folder-count flag is always set; the
		// attributes flag only when the node actually has attributes, because
		// fsck_hfs checks it in both directions.
		folder := HFSPlusCatalogFolder{
			RecordType:       HFSPlusFolderRecord,
			Flags:            HFSHasFolderCountMask | attrFlag(n),
			Valence:          uint32(len(n.children)),
			FolderID:         n.cnid,
			CreateDate:       ht[0],
			ContentModDate:   ht[1],
			AttributeModDate: ht[2],
			AccessDate:       ht[3],
			BSDInfo:          bsd,
			FolderCount:      subFolders,
		}
		setFolderFinderInfo(&folder, n)
		if n.bsdFlags&0x40 != 0 {
			setDocumentID(&folder.FinderInfo, uint32(n.cnid))
		}
		if n.bsdFlags&0x8000 != 0 {
			folder.UserInfo.FinderFlags |= 0x4000
		}
		return btRecord{key: key, payload: marshalBE(&folder)}
	}

	file := HFSPlusCatalogFile{
		RecordType:       HFSPlusFileRecord,
		Flags:            HFSThreadExistsMask | attrFlag(n),
		FileID:           n.cnid,
		CreateDate:       ht[0],
		ContentModDate:   ht[1],
		AttributeModDate: ht[2],
		AccessDate:       ht[3],
		BSDInfo:          bsd,
		DataFork:         b.forkFor(n),
		ResourceFork:     b.rsrcForkFor(n),
	}
	setFileFinderInfo(&file, n)
	if n.bsdFlags&0x40 != 0 {
		setDocumentID(&file.FinderInfo, uint32(n.cnid))
	}
	if n.bsdFlags&0x8000 != 0 {
		file.UserInfo.FinderFlags |= 0x4000
	}
	if n.bsdFlags&(0x2|0x20000) != 0 {
		file.Flags |= HFSFileLockedMask
	}
	switch {
	case n.isSymlink:
		file.UserInfo.FileType = SymLinkFileType
		file.UserInfo.FileCreator = SymLinkCreator
	case n.isLink:
		// A visible name for a linked file: no forks, and the indirect node's
		// catalog id in the special field.
		file.UserInfo.FileType = HardLinkFileType
		file.UserInfo.FileCreator = HFSPlusCreator
		file.BSDInfo.Special = n.linkRef
		file.Flags |= HFSHasLinkChainMask

		// A link record's owner and group fields are not an owner and a group:
		// they carry the neighbouring names in the chain. The real ownership
		// lives on the indirect node, which is where a reader resolving the
		// link ends up.
		file.BSDInfo.OwnerID = n.prevLink
		file.BSDInfo.GroupID = n.nextLink

		// Every link record shares the private directory's creation date.
		// fsck_hfs checks this exactly -- "Hard Link catalog entry N has bad
		// time X (should be Y)" -- because it is how a real hard link is told
		// from a file that merely carries the 'hlnk' type.
		file.CreateDate = b.privateDirTime

		// macOS writes these as immutable, read-only stubs: the content is not
		// theirs to change, and a reader must follow the link to reach it.
		file.BSDInfo.OwnerFlags = ufImmutable
		file.BSDInfo.FileMode = sIFREG | 0o444
	case n.isINode:
		// The indirect node holds the content, and counts the names.
		file.BSDInfo.Special = n.linkCount
		file.Flags |= HFSHasLinkChainMask
		file.Reserved1 = n.firstLink
	}
	return btRecord{key: key, payload: marshalBE(&file)}
}

// compressedFlag is UF_COMPRESSED when the node's content is held by a
// com.apple.decmpfs attribute rather than by its data fork.
//
// Like attrFlag it reads the node's own attributes rather than its Entry, which
// is what makes hard links come out right: buildHardLinks moves the attributes
// to the indirect node and clears them on every visible name, so the flag
// follows the content. A link record claiming compression while holding no
// attribute would be a file whose mode and contents disagree.
func compressedFlag(n *fileNode) uint8 {
	for _, a := range n.attrs {
		if a.name == decmpfsAttrName {
			return ufCompressed
		}
	}
	return 0
}

// threadRecord builds the thread record keyed by (cnid, emptyName) that
// points back to the object's real parent and name.
func (b *builder) threadRecord(n *fileNode) btRecord {
	key := encodeCatalogKey(n.cnid, "")
	recType := HFSPlusFileThreadRecord
	if n.isDir {
		recType = HFSPlusFolderThreadRecord
	}
	name := encodeUniStr(n.name)
	payload := make([]byte, 8+len(name))
	binary.BigEndian.PutUint16(payload[0:], uint16(recType))
	// payload[2:4] reserved = 0
	binary.BigEndian.PutUint32(payload[4:], uint32(n.parent))
	copy(payload[8:], name)
	return btRecord{key: key, payload: payload}
}

// encodeUniStr encodes a name as UniStr255: length(2) + UTF-16BE units.
func encodeUniStr(name string) []byte {
	units := encodeUTF16(name)
	out := make([]byte, 2+2*len(units))
	binary.BigEndian.PutUint16(out[0:], uint16(len(units)))
	for i, u := range units {
		binary.BigEndian.PutUint16(out[2+2*i:], u)
	}
	return out
}

// buildBitmap builds the allocation bitmap (1 bit/block, MSB-first, 1=used).
func (b *builder) buildBitmap(lay *layout) []byte {
	bitmap := make([]byte, lay.bitmapBlocks*uint32(b.blockSize))
	set := func(block uint32) { bitmap[block/8] |= 0x80 >> (block % 8) }
	setRange := func(start, count uint32) {
		for i := uint32(0); i < count; i++ {
			set(start + i)
		}
	}
	set(0) // volume header / boot blocks
	setRange(lay.bitmapStart, lay.bitmapBlocks)
	setRange(lay.extentsStart, lay.extentBlocks)
	setRange(lay.catalogStart, lay.catalogBlks)
	setRange(lay.attrStart, lay.attrBlks)
	for _, f := range b.fileNodes {
		setRange(f.dataStart, f.dataBlocks)
		setRange(f.rsrcStart, f.rsrcBlocks)
	}
	for _, n := range b.allNodes {
		for _, a := range n.attrs {
			setRange(a.start, a.blocks)
		}
	}
	set(lay.totalBlocks - 1) // alternate volume header
	return bitmap
}

// volumeHeader assembles the HFSX volume header.
func (b *builder) volumeHeader(volumeName string, lay *layout, _, _ builtTree) VolumeHeader {
	usedBlocks := b.countUsedBlocks(lay)
	now := toHFSTime(b.defaultTime)

	sigWord, version := HFSXSigWord, HFSXVersion
	if b.caseInsensitive {
		// A case-insensitive volume is plain HFS+, not HFSX: the signature and
		// version differ, and the catalog's compare type carries the rest.
		sigWord, version = HFSPlusSigWord, HFSPlusVersion
	}

	vh := VolumeHeader{
		Signature:        sigWord,
		Version:          version,
		Attributes:       0x80000100, // kHFSVolumeUnmountedMask + top bit, as newfs writes
		JournalInfoBlock: 0,
		CreateDate:       now,
		ModifyDate:       now,
		BackupDate:       0,
		CheckedDate:      now,
		FileCount:        b.fileCount,
		FolderCount:      b.folderCount,
		BlockSize:        uint32(b.blockSize),
		TotalBlocks:      lay.totalBlocks,
		FreeBlocks:       lay.totalBlocks - usedBlocks,
		NextAllocation:   lay.firstFree,
		RsrcClumpSize:    65536,
		DataClumpSize:    65536,
		NextCatalogID:    b.nextCNID,
		WriteCount:       0,
		EncodingsBitmap:  1,
	}
	copy(vh.LastMountedVersion[:], "10.0")

	// A stable, non-zero volume identifier: the caller's UUID when it supplied
	// one (its first eight bytes, big-endian, are the 64-bit HFS+ identifier),
	// otherwise one derived from the volume name and the fixed timestamp.
	if b.volumeUUID != ([16]byte{}) {
		vh.FinderInfo[6] = binary.BigEndian.Uint32(b.volumeUUID[0:4])
		vh.FinderInfo[7] = binary.BigEndian.Uint32(b.volumeUUID[4:8])
	} else {
		h := fnv.New64a()
		fmt.Fprintf(h, "%s-%d", volumeName, uint32(now))
		id := h.Sum64()
		vh.FinderInfo[6] = uint32(id >> 32)
		vh.FinderInfo[7] = uint32(id)
	}
	if vh.FinderInfo[6] == 0 && vh.FinderInfo[7] == 0 {
		vh.FinderInfo[7] = 1
	}

	// Allocation (bitmap) file.
	vh.AllocationFile = ForkData{
		LogicalSize: uint64(lay.bitmapBlocks) * uint64(b.blockSize),
		ClumpSize:   uint32(b.blockSize),
		TotalBlocks: lay.bitmapBlocks,
	}
	vh.AllocationFile.Extents[0] = ExtentDescriptor{StartBlock: lay.bitmapStart, BlockCount: lay.bitmapBlocks}

	// Extents overflow file (empty tree, one header node).
	// Each B-tree file's clump size is its own size; see packHeaderNode.
	vh.ExtentsFile = ForkData{
		LogicalSize: uint64(lay.extentBlocks) * uint64(b.blockSize),
		ClumpSize:   uint32(lay.extentBlocks) * uint32(b.blockSize),
		TotalBlocks: lay.extentBlocks,
	}
	vh.ExtentsFile.Extents[0] = ExtentDescriptor{StartBlock: lay.extentsStart, BlockCount: lay.extentBlocks}

	// Catalog file.
	vh.CatalogFile = ForkData{
		LogicalSize: uint64(lay.catalogBlks) * uint64(b.blockSize),
		ClumpSize:   uint32(lay.catalogBlks) * uint32(b.blockSize),
		TotalBlocks: lay.catalogBlks,
	}
	vh.CatalogFile.Extents[0] = ExtentDescriptor{StartBlock: lay.catalogStart, BlockCount: lay.catalogBlks}

	// The attributes file exists only when something needs it; a volume with no
	// extended attributes keeps an all-zero fork, as it did before this writer
	// could emit one. The startup file is always absent.
	if lay.attrBlks > 0 {
		vh.AttributesFile = ForkData{
			LogicalSize: uint64(lay.attrBlks) * uint64(b.blockSize),
			ClumpSize:   uint32(lay.attrBlks) * uint32(b.blockSize),
			TotalBlocks: lay.attrBlks,
		}
		vh.AttributesFile.Extents[0] = ExtentDescriptor{StartBlock: lay.attrStart, BlockCount: lay.attrBlks}
	}
	return vh
}

// countUsedBlocks counts the allocation blocks marked used in the bitmap.
func (b *builder) countUsedBlocks(lay *layout) uint32 {
	used := uint32(1) // block 0
	used += lay.bitmapBlocks
	used += lay.extentBlocks
	used += lay.catalogBlks
	used += lay.attrBlks
	for _, f := range b.fileNodes {
		used += f.dataBlocks + f.rsrcBlocks
	}
	for _, n := range b.allNodes {
		for _, a := range n.attrs {
			used += a.blocks
		}
	}
	used++ // alternate volume header (last block, in the trailing free region)
	return used
}

// toHFSTime converts a time to seconds since the HFS+ epoch (1904-01-01 UTC).
func toHFSTime(t time.Time) hfsTime {
	epoch := time.Date(1904, time.January, 1, 0, 0, 0, 0, time.UTC)
	if t.Before(epoch) {
		return 0
	}
	return hfsTime(t.Sub(epoch) / time.Second)
}
