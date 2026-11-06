// Extended attributes: the attributes file, an HFS+ special file holding a
// third B-tree keyed by (file id, attribute name).
//
// Attribute values live in one of three record shapes. A small value sits
// inside its own record; a larger one gets a fork of its own, described by a
// fork-data record; and a fork too fragmented for its eight inline extents
// spills into extents records. Note those extents records live in *this* tree,
// keyed by the same file id and name with a non-zero start block -- not in the
// extents overflow file, whose keys only ever name a data or resource fork.
package hfsplus

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// Attribute record types, from TN1150.
const (
	attrInlineData = 0x10
	attrForkData   = 0x20
	attrExtents    = 0x30
)

// attrKeyMinLen is the fixed part of an attribute key once walkLeaves has
// stripped the leading key length: pad(2) fileID(4) startBlock(4) nameLen(2).
const attrKeyMinLen = 12

// resourceForkAttrName is what macOS calls a file's resource fork when it is
// asked for the file's extended attributes. On HFS+ the resource fork is not an
// attribute at all -- it is a fork of the catalog record -- so it is synthesized
// under this name rather than read from the attributes file.
const resourceForkAttrName = "com.apple.ResourceFork"

// maxAttributeSize bounds a single attribute value. Sizes come from the volume,
// so they are attacker-controlled on an untrusted image; without a ceiling a
// corrupt record could ask for an arbitrary allocation.
const maxAttributeSize = common.MaximumAllocationSize

type attrKey struct {
	fileID CatalogNodeID
	name   string
}

// attrRecord is everything the attributes tree holds for one (file, name).
type attrRecord struct {
	inline []byte // set for an inline-data record

	fork    ForkData // set for a fork-data record
	hasFork bool

	// overflow holds this attribute's extents records, sorted by start block.
	overflow []overflowRun
}

// loadAttributes walks the attributes B-tree once and caches every record,
// keyed by (file id, attribute name). It is a no-op after the first call, and
// on a volume with no attributes file.
func (v *Volume) loadAttributes() (err error) {
	if v.attributes != nil {
		return nil
	}
	v.attributes = make(map[attrKey]*attrRecord)
	v.attrNames = make(map[CatalogNodeID][]string)
	// Do not cache a partial/empty result after a failed read. A later security
	// capture must see the same failure, not report the ACL as absent.
	defer func() {
		if err != nil {
			v.attributes, v.attrNames = nil, nil
		}
	}()

	if v.hdr.AttributesFile.LogicalSize == 0 {
		return nil
	}

	fork, err := v.forkReaderFor(HFSAttributesFileID, forkTypeData, v.hdr.AttributesFile)
	if err != nil {
		return fmt.Errorf("failed to resolve attributes fork: %w", err)
	}
	tree, err := openBTree(fork)
	if err != nil {
		return fmt.Errorf("failed to open attributes B-tree: %w", err)
	}

	err = tree.walkLeaves(func(rec leafRecord) error {
		fileID, startBlock, name, err := parseAttrKey(rec.key)
		if err != nil {
			return err
		}
		if len(rec.data) < 4 {
			return fmt.Errorf("attribute record for file %d %q is %d bytes", fileID, name, len(rec.data))
		}

		key := attrKey{fileID: fileID, name: name}
		entry := v.attributes[key]
		if entry == nil {
			entry = &attrRecord{}
			v.attributes[key] = entry
			v.attrNames[fileID] = append(v.attrNames[fileID], name)
		}

		switch recordType := binary.BigEndian.Uint32(rec.data); recordType {
		case attrInlineData:
			// recordType(4) reserved(8) attrSize(4) then the value.
			if len(rec.data) < 16 {
				return fmt.Errorf("inline attribute %q on file %d is %d bytes, too short for its header", name, fileID, len(rec.data))
			}
			size := binary.BigEndian.Uint32(rec.data[12:16])
			if uint64(size) > maxAttributeSize {
				return fmt.Errorf("inline attribute %q on file %d claims %d bytes", name, fileID, size)
			}
			if int(size) > len(rec.data)-16 {
				return fmt.Errorf("inline attribute %q on file %d claims %d bytes but its record holds %d", name, fileID, size, len(rec.data)-16)
			}
			// walkLeaves hands out sub-slices of one buffer it reuses for every
			// node, so a retained value would silently become the next node's
			// bytes. Copy out.
			entry.inline = bytes.Clone(rec.data[16 : 16+size])

		case attrForkData:
			// recordType(4) reserved(4) then an 80-byte fork.
			if len(rec.data) < 8+80 {
				return fmt.Errorf("fork attribute %q on file %d is %d bytes, too short for a fork", name, fileID, len(rec.data))
			}
			entry.fork = parseForkData(rec.data[8:])
			entry.hasFork = true

		case attrExtents:
			// recordType(4) reserved(4) then eight extent descriptors.
			if len(rec.data) < 8+64 {
				return fmt.Errorf("extents attribute %q on file %d is %d bytes, too short for an extent record", name, fileID, len(rec.data))
			}
			run := overflowRun{startBlock: startBlock}
			for i := range run.extents {
				run.extents[i].StartBlock = binary.BigEndian.Uint32(rec.data[8+i*8:])
				run.extents[i].BlockCount = binary.BigEndian.Uint32(rec.data[8+i*8+4:])
			}
			entry.overflow = append(entry.overflow, run)

		default:
			// An unknown record type is not fatal: the rest of the tree is
			// still readable, and refusing the whole volume over one record
			// would be worse than reporting the attributes we do understand.
			return nil
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to walk attributes B-tree: %w", err)
	}

	for fileID := range v.attrNames {
		sort.Strings(v.attrNames[fileID])
	}
	for key := range v.attributes {
		runs := v.attributes[key].overflow
		sort.Slice(runs, func(i, j int) bool { return runs[i].startBlock < runs[j].startBlock })
	}

	return nil
}

// parseAttrKey decodes an attribute key; the leading key length has already
// been stripped by walkLeaves.
func parseAttrKey(key []byte) (fileID CatalogNodeID, startBlock uint32, name string, err error) {
	if len(key) < attrKeyMinLen {
		return 0, 0, "", fmt.Errorf("attribute key too short: %d bytes", len(key))
	}
	fileID = CatalogNodeID(binary.BigEndian.Uint32(key[2:]))
	startBlock = binary.BigEndian.Uint32(key[6:])

	nameLen := int(binary.BigEndian.Uint16(key[10:]))
	if len(key) < attrKeyMinLen+2*nameLen {
		return 0, 0, "", fmt.Errorf("attribute key name truncated: want %d chars, have %d bytes", nameLen, len(key)-attrKeyMinLen)
	}
	units := make([]uint16, nameLen)
	for i := range units {
		units[i] = binary.BigEndian.Uint16(key[attrKeyMinLen+2*i:])
	}
	// UniStr255.String allocates a new string, so this does not alias the
	// walkLeaves buffer.
	name = (&UniStr255{Length: uint16(nameLen), UniChar: units}).String()

	return fileID, startBlock, name, nil
}

// parseForkData decodes an 80-byte HFSPlusForkData.
func parseForkData(data []byte) ForkData {
	var fork ForkData
	fork.LogicalSize = binary.BigEndian.Uint64(data)
	fork.ClumpSize = binary.BigEndian.Uint32(data[8:])
	fork.TotalBlocks = binary.BigEndian.Uint32(data[12:])
	for i := range fork.Extents {
		fork.Extents[i].StartBlock = binary.BigEndian.Uint32(data[16+i*8:])
		fork.Extents[i].BlockCount = binary.BigEndian.Uint32(data[16+i*8+4:])
	}
	return fork
}

// attributeValue returns the bytes of one attribute.
func (v *Volume) attributeValue(fileID CatalogNodeID, name string) ([]byte, error) {
	rec := v.attributes[attrKey{fileID: fileID, name: name}]
	if rec == nil {
		return nil, fmt.Errorf("file %d has no attribute %q", fileID, name)
	}
	if rec.inline != nil {
		return rec.inline, nil
	}
	if !rec.hasFork {
		return nil, fmt.Errorf("attribute %q on file %d has neither inline data nor a fork", name, fileID)
	}

	if rec.fork.LogicalSize > maxAttributeSize {
		return nil, fmt.Errorf("attribute %q on file %d claims %d bytes", name, fileID, rec.fork.LogicalSize)
	}

	// An attribute's spilled extents are keyed into this tree, not the extents
	// overflow file, so they are assembled here rather than by forkReaderFor.
	extents := inlineExtents(rec.fork)
	var blocks uint32
	for _, ext := range extents {
		blocks += ext.BlockCount
	}
	for _, run := range rec.overflow {
		if run.startBlock != blocks {
			continue // runs are sorted; only append contiguous coverage
		}
		for _, ext := range run.extents {
			if ext.BlockCount == 0 {
				break
			}
			extents = append(extents, ext)
			blocks += ext.BlockCount
		}
	}
	if blocks < rec.fork.TotalBlocks {
		return nil, fmt.Errorf("attribute %q on file %d: extents cover %d of %d blocks", name, fileID, blocks, rec.fork.TotalBlocks)
	}

	reader, err := newForkReader(v.dev, v.blockSize, rec.fork.LogicalSize, extents)
	if err != nil {
		return nil, fmt.Errorf("attribute %q on file %d: %w", name, fileID, err)
	}
	value := make([]byte, rec.fork.LogicalSize)
	if len(value) == 0 {
		return value, nil
	}
	if _, err := reader.ReadAt(value, 0); err != nil {
		return nil, fmt.Errorf("failed to read attribute %q on file %d: %w", name, fileID, err)
	}
	return value, nil
}

// entryFileID is the catalog node id attributes are keyed by. For a hard link
// this is already the target iNode's id, because resolveHardLinks replaced the
// entry's catalog record with the target's -- which is where a linked file's
// attributes actually live.
func entryFileID(e *entry) (CatalogNodeID, bool) {
	switch {
	case e.isDir && e.folder != nil:
		return e.folder.FolderID, true
	case !e.isDir && e.file != nil:
		return e.file.FileID, true
	default:
		return 0, false
	}
}

// xattrs returns every extended attribute of a resolved entry.
func (v *Volume) xattrs(e *entry) (map[string][]byte, error) {
	fileID, ok := entryFileID(e)
	if !ok {
		return nil, fmt.Errorf("entry has no catalog record")
	}

	if err := v.loadAttributes(); err != nil {
		return nil, err
	}

	attrs := make(map[string][]byte, len(v.attrNames[fileID])+1)
	for _, name := range v.attrNames[fileID] {
		value, err := v.attributeValue(fileID, name)
		if err != nil {
			return nil, err
		}
		attrs[name] = value
	}

	if err := addCatalogFinderInfo(attrs, e); err != nil {
		return nil, err
	}

	// The resource fork is a fork of the catalog record on HFS+, but every tool
	// on the platform reports it as an attribute, so present it as one. Note
	// this is what makes `extract --xattrs` recover a resource fork, and what
	// lets a compressed file's fork be recognized for what it is.
	if !e.isDir && e.file != nil && e.file.ResourceFork.LogicalSize > 0 {
		fork, err := v.resourceForkReader(e)
		if err != nil {
			return nil, err
		}
		if fork.Size() > maxAttributeSize {
			return nil, fmt.Errorf("resource fork of file %d is %d bytes", fileID, fork.Size())
		}
		value := make([]byte, fork.Size())
		if _, err := fork.ReadAt(value, 0); err != nil {
			return nil, fmt.Errorf("failed to read resource fork of file %d: %w", fileID, err)
		}
		attrs[resourceForkAttrName] = value
	}

	return attrs, nil
}

// resourceForkReader opens a file's resource fork.
func (v *Volume) resourceForkReader(e *entry) (*forkReader, error) {
	if e.isDir || e.file == nil {
		return nil, fmt.Errorf("entry has no resource fork")
	}
	return v.forkReaderFor(e.file.FileID, forkTypeResource, e.file.ResourceFork)
}
