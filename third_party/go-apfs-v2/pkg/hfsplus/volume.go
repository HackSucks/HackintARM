// Package hfsplus is a pure-Go, read-only HFS Plus / HFSX file system
// engine. It parses the volume header and catalog B-tree, reads file
// content through the data fork's inline extents plus the extents
// overflow B-tree, and resolves symlinks and hard links.
//
// Catalog and on-disk type definitions are adapted from blacktop/go-apfs's
// hfsplus package (Apache-2.0); file-data reading, extents overflow
// support, link resolution and the io/fs adapter are new.
package hfsplus

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	// volumeHeaderOffset is the fixed byte offset of the volume header
	// within the volume (partition).
	volumeHeaderOffset = 1024

	// metadataDirName is the private directory that holds iNodeNNNN
	// hard-link target files. The name starts with four NUL characters so
	// it sorts first and stays out of sight.
	metadataDirName = "\x00\x00\x00\x00HFS+ Private Data"

	// dirMetadataDirName holds directory hard-link targets.
	dirMetadataDirName = ".HFS+ Private Directory Data\r"

	// Fork types for extents overflow keys.
	forkTypeData     = 0x00
	forkTypeResource = 0xFF
)

// Volume is a read-only HFS Plus / HFSX volume. It implements fs.FS,
// fs.ReadDirFS, fs.StatFS and fs.ReadFileFS (see fs.go).
type Volume struct {
	dev       io.ReaderAt
	hdr       VolumeHeader
	blockSize int64

	caseSensitive bool

	catalogTree *btree
	extentsTree *btree

	// overflowExtents caches the fully-walked extents overflow B-tree:
	// (forkType, fileID) -> extent runs sorted by start block.
	overflowExtents map[overflowKey][]overflowRun

	// attributes caches the fully-walked attributes B-tree, and attrNames
	// lists each file's attribute names in order. Both are nil until the
	// first attribute lookup; see loadAttributes.
	attributes map[attrKey]*attrRecord
	attrNames  map[CatalogNodeID][]string

	root       *entry
	volumeName string
}

type overflowKey struct {
	forkType uint8
	fileID   CatalogNodeID
}

type overflowRun struct {
	startBlock uint32
	extents    ExtentRecord
}

// entry is one resolved node of the catalog tree.
type entry struct {
	name   string
	isDir  bool
	folder *HFSPlusCatalogFolder // set when isDir
	file   *HFSPlusCatalogFile   // set for files; hard links point at the resolved iNode record

	// isDirLink marks an unresolved directory hard link ('fdrp').
	isDirLink bool
	// brokenLink holds the iNode number of a hard link whose target file
	// could not be found.
	brokenLink uint32

	children []*entry // sorted by name; nil for files
}

// New parses the HFS Plus / HFSX volume whose partition starts at offset 0
// of device, and loads the catalog.
func New(device io.ReaderAt) (*Volume, error) {
	v := &Volume{dev: device}

	hdrBuf := make([]byte, 512)
	if _, err := device.ReadAt(hdrBuf, volumeHeaderOffset); err != nil {
		return nil, fmt.Errorf("failed to read volume header: %w", err)
	}
	if err := binary.Read(bytes.NewReader(hdrBuf), binary.BigEndian, &v.hdr); err != nil {
		return nil, fmt.Errorf("failed to parse volume header: %w", err)
	}

	switch {
	case v.hdr.Signature == HFSPlusSigWord && v.hdr.Version == HFSPlusVersion:
		v.caseSensitive = false
	case v.hdr.Signature == HFSXSigWord && v.hdr.Version >= HFSXVersion:
		// HFSX may be either; the catalog header's key compare type decides.
		v.caseSensitive = true
	default:
		return nil, fmt.Errorf("not an HFS+ volume: signature %s version %d", v.hdr.Signature, v.hdr.Version)
	}

	if v.hdr.BlockSize < 512 || v.hdr.BlockSize&(v.hdr.BlockSize-1) != 0 {
		return nil, fmt.Errorf("invalid allocation block size %d", v.hdr.BlockSize)
	}
	v.blockSize = int64(v.hdr.BlockSize)

	// The extents overflow file's own extents always fit in the volume
	// header, so it can be opened without overflow resolution.
	if v.hdr.ExtentsFile.LogicalSize > 0 {
		extFork, err := newForkReader(v.dev, v.blockSize, v.hdr.ExtentsFile.LogicalSize, inlineExtents(v.hdr.ExtentsFile))
		if err != nil {
			return nil, fmt.Errorf("extents overflow file: %w", err)
		}
		tree, err := openBTree(extFork)
		if err != nil {
			return nil, fmt.Errorf("failed to open extents overflow B-tree: %w", err)
		}
		v.extentsTree = tree
	}

	catFork, err := v.forkReaderFor(HFSCatalogFileID, forkTypeData, v.hdr.CatalogFile)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve catalog fork: %w", err)
	}
	v.catalogTree, err = openBTree(catFork)
	if err != nil {
		return nil, fmt.Errorf("failed to open catalog B-tree: %w", err)
	}

	if v.hdr.Signature == HFSXSigWord {
		v.caseSensitive = v.catalogTree.header.KeyCompareType == HFSBinaryCompare
	}

	if err := v.loadCatalog(); err != nil {
		return nil, err
	}

	return v, nil
}

// Name returns the volume name (the root folder's catalog name).
func (v *Volume) Name() string { return v.volumeName }

// FileCount returns the number of files from the volume header.
func (v *Volume) FileCount() uint32 { return v.hdr.FileCount }

// FolderCount returns the number of folders from the volume header
// (not including the root folder).
func (v *Volume) FolderCount() uint32 { return v.hdr.FolderCount }

// CaseSensitive reports whether catalog names are compared
// case-sensitively (HFSX with binary compare).
func (v *Volume) CaseSensitive() bool { return v.caseSensitive }

// Created returns the volume creation date.
func (v *Volume) Created() time.Time { return v.hdr.CreateDate.Time() }

// Modified returns the volume's last modification date.
func (v *Volume) Modified() time.Time { return v.hdr.ModifyDate.Time() }

// UUID returns the 64-bit volume identifier from finderInfo[6..7] as a
// hex string, or "" when the volume has none.
func (v *Volume) UUID() string {
	id := uint64(v.hdr.FinderInfo[6])<<32 | uint64(v.hdr.FinderInfo[7])
	if id == 0 {
		return ""
	}
	return fmt.Sprintf("%016X", id)
}

// Header returns a copy of the parsed volume header.
func (v *Volume) Header() VolumeHeader { return v.hdr }

// loadCatalog walks the catalog B-tree once and builds the entry tree.
func (v *Volume) loadCatalog() error {
	type rawFolder struct {
		parentID CatalogNodeID
		entry    *entry
	}

	var folders []rawFolder
	byFolderID := make(map[CatalogNodeID]*entry)
	filesByParent := make(map[CatalogNodeID][]*entry)

	err := v.catalogTree.walkLeaves(func(rec leafRecord) error {
		parentID, name, err := parseCatalogKey(rec.key)
		if err != nil {
			return err
		}
		if len(rec.data) < 2 {
			return fmt.Errorf("catalog record for %q too short", name)
		}

		switch RecordType(binary.BigEndian.Uint16(rec.data)) {
		case HFSPlusFolderRecord:
			var folder HFSPlusCatalogFolder
			if err := binary.Read(bytes.NewReader(rec.data), binary.BigEndian, &folder); err != nil {
				return fmt.Errorf("failed to parse folder record %q: %w", name, err)
			}
			e := &entry{name: name, isDir: true, folder: &folder}
			byFolderID[folder.FolderID] = e
			folders = append(folders, rawFolder{parentID: parentID, entry: e})

		case HFSPlusFileRecord:
			var file HFSPlusCatalogFile
			if err := binary.Read(bytes.NewReader(rec.data), binary.BigEndian, &file); err != nil {
				return fmt.Errorf("failed to parse file record %q: %w", name, err)
			}
			e := &entry{name: name, file: &file}
			filesByParent[parentID] = append(filesByParent[parentID], e)

		case HFSPlusFolderThreadRecord, HFSPlusFileThreadRecord:
			// Thread records only map IDs back to names; not needed here.
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to walk catalog B-tree: %w", err)
	}

	root, ok := byFolderID[HFSRootFolderID]
	if !ok {
		return fmt.Errorf("catalog has no root folder")
	}
	v.root = root
	v.volumeName = root.name

	// Attach children to folders.
	for _, rf := range folders {
		if rf.entry == root {
			continue
		}
		parent, ok := byFolderID[rf.parentID]
		if !ok {
			continue // orphan; skip
		}
		parent.children = append(parent.children, rf.entry)
	}
	for parentID, files := range filesByParent {
		parent, ok := byFolderID[parentID]
		if !ok {
			continue
		}
		parent.children = append(parent.children, files...)
	}

	v.resolveHardLinks()
	v.hideMetadataEntries()

	// Sort children by name, as fs.ReadDirFS requires.
	for _, e := range byFolderID {
		sort.Slice(e.children, func(i, j int) bool { return e.children[i].name < e.children[j].name })
	}

	return nil
}

// resolveHardLinks replaces 'hlnk' indirect-node references with the
// catalog file record of the iNodeNNNN file they point at.
func (v *Volume) resolveHardLinks() {
	inodes := make(map[uint32]*HFSPlusCatalogFile)
	if private := v.rootChildNamed(metadataDirName); private != nil {
		for _, child := range private.children {
			if child.file == nil {
				continue
			}
			numStr, ok := strings.CutPrefix(child.name, "iNode")
			if !ok {
				continue
			}
			num, err := strconv.ParseUint(numStr, 10, 32)
			if err != nil {
				continue
			}
			inodes[uint32(num)] = child.file
		}
	}

	var walk func(e *entry)
	walk = func(e *entry) {
		for _, child := range e.children {
			if child.isDir {
				walk(child)
				continue
			}
			f := child.file
			if f == nil {
				continue
			}
			switch {
			case f.UserInfo.FileType == HardLinkFileType && f.UserInfo.FileCreator == HFSPlusCreator:
				if target, ok := inodes[f.BSDInfo.Special]; ok {
					child.file = target
				} else {
					child.brokenLink = f.BSDInfo.Special
				}
			case f.UserInfo.FileType == DirLinkFileType && f.UserInfo.FileCreator == DirLinkCreator:
				child.isDirLink = true
			}
		}
	}
	walk(v.root)
}

// hideMetadataEntries removes HFS+ housekeeping entries from the root
// folder listing: the private hard-link directories and the journal
// files, which macOS also hides.
func (v *Volume) hideMetadataEntries() {
	hidden := map[string]bool{
		metadataDirName:       true,
		dirMetadataDirName:    true,
		".journal":            true,
		".journal_info_block": true,
	}
	kept := v.root.children[:0]
	for _, child := range v.root.children {
		if !hidden[child.name] {
			kept = append(kept, child)
		}
	}
	v.root.children = kept
}

// rootChildNamed finds a direct child of the root folder by exact name.
func (v *Volume) rootChildNamed(name string) *entry {
	for _, child := range v.root.children {
		if child.name == catalogName(name) || child.name == name {
			return child
		}
	}
	return nil
}

// lookup resolves a slash-separated path (relative to the root, "." for
// the root itself) to an entry. Symlinks are not followed.
func (v *Volume) lookup(name string) (*entry, error) {
	current := v.root
	if name == "." || name == "" {
		return current, nil
	}

	for _, part := range strings.Split(name, "/") {
		if !current.isDir {
			return nil, fmt.Errorf("%q is not a directory", posixName(current.name))
		}
		// Stored names are decomposed, so a caller passing a precomposed one --
		// which is what a Go string literal or a path from most systems holds --
		// would not match without this.
		normalized, err := NormalizeLookupName(part)
		if err != nil {
			return nil, fmt.Errorf("component %q: %w", part, err)
		}
		next := findChild(current, catalogName(normalized), v.caseSensitive)
		if next == nil && part != catalogName(part) {
			// A volume written by something that stored the colon verbatim.
			next = findChild(current, normalized, v.caseSensitive)
		}
		if next == nil {
			return nil, fmt.Errorf("no such file or directory: %q", part)
		}
		current = next
	}

	return current, nil
}

// findChild locates a child by name. Case-insensitive volumes fall back
// to a Unicode case fold when the exact name does not match.
func findChild(dir *entry, name string, caseSensitive bool) *entry {
	// Children are sorted by name; exact match via binary search.
	i := sort.Search(len(dir.children), func(i int) bool { return dir.children[i].name >= name })
	if i < len(dir.children) && dir.children[i].name == name {
		return dir.children[i]
	}
	if caseSensitive {
		return nil
	}
	for _, child := range dir.children {
		if compareNameUnits(utf16.Encode([]rune(child.name)), utf16.Encode([]rune(name)), false) == 0 {
			return child
		}
	}
	return nil
}

// parseCatalogKey decodes a catalog key (parent ID + Unicode name); the
// leading key length has already been stripped.
func parseCatalogKey(key []byte) (CatalogNodeID, string, error) {
	if len(key) < 6 {
		return 0, "", fmt.Errorf("catalog key too short: %d bytes", len(key))
	}
	parentID := CatalogNodeID(binary.BigEndian.Uint32(key))
	nameLen := int(binary.BigEndian.Uint16(key[4:]))
	if len(key) < 6+2*nameLen {
		return 0, "", fmt.Errorf("catalog key name truncated: want %d chars, have %d bytes", nameLen, len(key)-6)
	}
	units := make([]uint16, nameLen)
	for i := range units {
		units[i] = binary.BigEndian.Uint16(key[6+2*i:])
	}
	name := (&UniStr255{Length: uint16(nameLen), UniChar: units}).String()
	return parentID, name, nil
}

// inlineExtents returns the non-empty extents stored inline in a fork.
func inlineExtents(fork ForkData) []ExtentDescriptor {
	var extents []ExtentDescriptor
	for _, ext := range fork.Extents {
		if ext.BlockCount == 0 {
			break
		}
		extents = append(extents, ext)
	}
	return extents
}

// forkReaderFor builds an io.ReaderAt over a fork, consulting the extents
// overflow B-tree when the inline extents do not cover the whole fork.
func (v *Volume) forkReaderFor(fileID CatalogNodeID, forkType uint8, fork ForkData) (*forkReader, error) {
	extents := inlineExtents(fork)

	var blocks uint32
	for _, ext := range extents {
		blocks += ext.BlockCount
	}

	if blocks < fork.TotalBlocks {
		if err := v.loadOverflowExtents(); err != nil {
			return nil, err
		}
		for _, run := range v.overflowExtents[overflowKey{forkType: forkType, fileID: fileID}] {
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
		if blocks < fork.TotalBlocks {
			return nil, fmt.Errorf("file %d fork %#x: extents cover %d of %d blocks", fileID, forkType, blocks, fork.TotalBlocks)
		}
	}

	reader, err := newForkReader(v.dev, v.blockSize, fork.LogicalSize, extents)
	if err != nil {
		return nil, fmt.Errorf("file %d fork %#x: %w", fileID, forkType, err)
	}
	return reader, nil
}

// loadOverflowExtents walks the extents overflow B-tree once and caches
// every record, keyed by (forkType, fileID).
func (v *Volume) loadOverflowExtents() error {
	if v.overflowExtents != nil {
		return nil
	}
	pending := make(map[overflowKey][]overflowRun)
	if v.extentsTree == nil {
		v.overflowExtents = pending
		return nil
	}

	err := v.extentsTree.walkLeaves(func(rec leafRecord) error {
		// Key: forkType(1) pad(1) fileID(4) startBlock(4).
		if len(rec.key) < 10 || len(rec.data) < 64 {
			return fmt.Errorf("malformed extents overflow record (key %d bytes, data %d bytes)", len(rec.key), len(rec.data))
		}
		key := overflowKey{
			forkType: rec.key[0],
			fileID:   CatalogNodeID(binary.BigEndian.Uint32(rec.key[2:])),
		}
		run := overflowRun{startBlock: binary.BigEndian.Uint32(rec.key[6:])}
		for i := range run.extents {
			run.extents[i].StartBlock = binary.BigEndian.Uint32(rec.data[i*8:])
			run.extents[i].BlockCount = binary.BigEndian.Uint32(rec.data[i*8+4:])
		}
		pending[key] = append(pending[key], run)
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to walk extents overflow B-tree: %w", err)
	}

	// Leaf order already sorts by (forkType, fileID, startBlock), but be
	// defensive about it.
	for key := range pending {
		runs := pending[key]
		sort.Slice(runs, func(i, j int) bool { return runs[i].startBlock < runs[j].startBlock })
	}

	// Publish only a complete successful walk; retries must retain malformed
	// records and provider failures instead of accepting a partial cache.
	v.overflowExtents = pending
	return nil
}

// dataForkReader opens a resolved file entry's content: its data fork, or a
// decompressing reader when the file is transparently compressed.
func (v *Volume) dataForkReader(e *entry) (fileReader, error) {
	if e.isDir {
		return nil, fmt.Errorf("is a directory")
	}
	if e.isDirLink {
		return nil, fmt.Errorf("directory hard links are not supported")
	}
	if e.brokenLink != 0 {
		return nil, fmt.Errorf("hard link target iNode%d not found", e.brokenLink)
	}
	if e.file == nil {
		return nil, fmt.Errorf("entry has no catalog file record")
	}
	if e.file.BSDInfo.OwnerFlags&ufCompressed != 0 {
		return v.decmpfsReader(e)
	}
	return v.forkReaderFor(e.file.FileID, forkTypeData, e.file.DataFork)
}

// readlink returns the target of a symlink entry (the data fork content).
func (v *Volume) readlink(e *entry) (string, error) {
	if e.isDir || e.file == nil || e.file.BSDInfo.FileMode&sIFMT != sIFLNK {
		return "", fmt.Errorf("not a symlink")
	}
	fork, err := v.dataForkReader(e)
	if err != nil {
		return "", err
	}
	target := make([]byte, fork.Size())
	if len(target) == 0 {
		return "", nil
	}
	if _, err := fork.ReadAt(target, 0); err != nil {
		return "", err
	}
	return string(target), nil
}
