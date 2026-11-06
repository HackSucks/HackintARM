package apfs

import (
	"container/list"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// FileSystemBTree represents the APFS file system B-tree
type FileSystemBTree struct {
	// The IO handle
	IOHandle *IOHandle

	// The encryption context
	EncryptionContext *EncryptionContext

	// The object map B-tree (for transaction identifier mapping)
	ObjectMapBTree *ObjectMapBTree

	// The block number of B-tree root node (actually a virtual OID)
	RootNodeOID uint64

	// The volume's transaction identifier (used for object map lookups)
	VolumeTransactionID uint64

	// Flag to indicate case folding should be used
	UseCaseFolding bool

	// FextTreeOID is the block number of the file extent tree
	// (apfs_fext_tree_oid). Sealed volumes keep their file extents there
	// rather than in the file-system tree; zero when the tree is absent.
	FextTreeOID uint64

	// FextTreeType is the object type of the file extent tree
	// (apfs_fext_tree_type). Bit 0x40000000 marks it as a physical tree.
	FextTreeType uint32

	// dirIndexes caches, for the directories looked up most recently, their
	// entries grouped by name hash (see directoryIndex).
	dirIndexMu  sync.Mutex
	dirIndexes  map[uint64]*list.Element
	dirIndexLRU *list.List

	// Note: Optional caching layers can be added for performance:
	// - DataBlockVector: Vector-based block reading (currently using direct I/O)
	// - DataBlockCache: LRU cache for data blocks (currently uncached)
	// - NodeCache: LRU cache for B-tree nodes (currently uncached)
	// These are performance optimizations, not required for correctness.
}

// NewFileSystemBTree creates a new file system B-tree
func NewFileSystemBTree(
	ioHandle *IOHandle,
	encryptionContext *EncryptionContext,
	objectMapBTree *ObjectMapBTree,
	rootNodeOID uint64,
	volumeTransactionID uint64,
	useCaseFolding bool,
) *FileSystemBTree {
	return &FileSystemBTree{
		IOHandle:            ioHandle,
		EncryptionContext:   encryptionContext,
		ObjectMapBTree:      objectMapBTree,
		RootNodeOID:         rootNodeOID,
		VolumeTransactionID: volumeTransactionID,
		UseCaseFolding:      useCaseFolding,
	}
}

// RootNode retrieves the root node of the file system B-tree
func (bt *FileSystemBTree) RootNode(
	reader io.ReaderAt,
) (*BTreeNode, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	// RootNodeOID is actually a virtual OID that needs to be resolved
	// through the volume's object map B-tree to get the physical block address
	// Per drat: get_btree_phys_omap_entry(vol_omap_root_node, apfs_root_tree_oid, apfs_o.o_xid)
	descriptor, err := bt.ObjectMapBTree.DescriptorByObjectIdentifier(
		reader,
		bt.RootNodeOID,         // This is a virtual OID
		bt.VolumeTransactionID, // Use the volume's transaction ID per drat
	)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve file system root tree OID %d: %w", bt.RootNodeOID, err)
	}

	if descriptor == nil {
		return nil, fmt.Errorf("file system root tree OID %d not found in object map", bt.RootNodeOID)
	}

	physicalAddress := descriptor.Value.ObjectPhysicalAddress

	// Read the root node using the resolved physical block address
	node, err := ReadBTreeNode(reader, bt.IOHandle, bt.EncryptionContext, physicalAddress)
	if err != nil {
		return nil, fmt.Errorf("unable to read root node at block %d (virtual OID %d): %w", physicalAddress, bt.RootNodeOID, err)
	}

	return node, nil
}

// SubNode retrieves a sub-node (child node) by block number
// The blockNumber can be either a physical block or virtual OID depending on the B-tree type
func (bt *FileSystemBTree) SubNode(
	reader io.ReaderAt,
	blockNumber uint64,
) (*BTreeNode, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	// Try to read directly first (assume it's a physical block number)
	node, err := ReadBTreeNode(reader, bt.IOHandle, bt.EncryptionContext, blockNumber)
	if err == nil {
		// Successfully read, it was a physical block
		return node, nil
	}

	// If direct read failed and we have an ObjectMap, try resolving as virtual OID
	if bt.ObjectMapBTree != nil {
		physicalAddress, omapErr := bt.ObjectMapBTree.PhysicalAddressForOID(
			reader,
			blockNumber,
			bt.VolumeTransactionID,
		)
		if omapErr == nil {
			// Successfully resolved via OMap
			node, readErr := ReadBTreeNode(reader, bt.IOHandle, bt.EncryptionContext, physicalAddress)
			if readErr == nil {
				return node, nil
			}
			return nil, fmt.Errorf("unable to read sub-node at resolved physical block %d (virtual OID %d): %w", physicalAddress, blockNumber, readErr)
		}
	}

	// Both attempts failed, return original error
	return nil, fmt.Errorf("unable to read sub-node at block %d: %w", blockNumber, err)
}

// SubNodeOIDFromEntry extracts the sub-node block number from a branch entry
// In branch nodes, the value data contains the block number of the child node
func (bt *FileSystemBTree) SubNodeOIDFromEntry(
	reader io.ReaderAt,
	entry *BTreeEntry,
) (uint64, error) {
	if bt == nil {
		return 0, fmt.Errorf("invalid file system B-tree")
	}

	if entry == nil {
		return 0, fmt.Errorf("invalid B-tree entry")
	}

	// In branch nodes, value data holds the child reference.  On a sealed
	// volume (BTNODE_HASHED) that reference is a btree_node_ref_t: the 8-byte
	// OID followed by a 32-byte hash of the child node.  Unsealed trees store
	// only the OID.  The hash is not needed to read the tree.
	hashed := len(entry.ValueData) == 40
	if len(entry.ValueData) != 8 && !hashed {
		return 0, fmt.Errorf("invalid value data size for branch entry: %d", len(entry.ValueData))
	}

	// Read the OID (little-endian)
	// Per drat (btree.c:377-378), in file system B-trees, child node references
	// are ALWAYS virtual OIDs that must be resolved through the volume's object map
	// (unlike container object map B-trees which use bit 63 to indicate virtual vs physical)
	virtualOID := binary.LittleEndian.Uint64(entry.ValueData[0:8])
	// In a hashed (sealed) tree the stored reference is relative to the tree's
	// root OID: child = binv_child_oid + apfs_root_tree_oid (apfs-fuse BTree.cpp).
	if hashed {
		virtualOID += bt.RootNodeOID
	}

	// Resolve through the volume's object map B-tree
	if bt.ObjectMapBTree == nil {
		return 0, fmt.Errorf("no object map B-tree available to resolve virtual OID %d", virtualOID)
	}

	descriptor, err := bt.ObjectMapBTree.DescriptorByObjectIdentifier(
		reader,
		virtualOID,
		bt.VolumeTransactionID,
	)
	if err != nil {
		return 0, fmt.Errorf("unable to resolve virtual OID %d: %w", virtualOID, err)
	}
	if descriptor == nil {
		return 0, fmt.Errorf("virtual OID %d not found in object map", virtualOID)
	}

	return descriptor.Value.ObjectPhysicalAddress, nil
}

// FileExtents retrieves file extents for a given identifier
func (bt *FileSystemBTree) FileExtents(
	reader io.ReaderAt,
	identifier uint64,
	xid uint64,
) ([]*FileExtent, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	// Use comprehensive tree traversal to get ALL records for this OID
	allRecords, err := bt.AllRecordsForOID(reader, identifier)
	if err != nil {
		return nil, fmt.Errorf("unable to get records for OID %d: %w", identifier, err)
	}

	// Filter for file extent records only
	extents := make([]*FileExtent, 0)

	for _, entry := range allRecords {
		dataType, err := ExtractDataTypeFromKey(entry.KeyData)
		if err != nil {
			continue
		}

		if dataType == FileSystemRecordTypeFileExtent {
			entryID, logicalAddr, err := ParseFileExtentKey(entry.KeyData)
			if err != nil {
				continue
			}

			if entryID == identifier {
				// Parse the file extent value
				extent, err := ParseFileExtentValue(entry.ValueData)
				if err != nil {
					return nil, fmt.Errorf("unable to parse file extent value: %w", err)
				}

				// Set the logical offset from the key
				extent.LogicalOffset = logicalAddr

				extents = append(extents, extent)
			}
		}
	}

	// The file-system tree of a sealed volume is hashed (BTNODE_HASHED) and
	// carries no file extents: they live in a separate physical file extent
	// tree referenced by apfs_fext_tree_oid. Consult it when the file-system
	// tree produced none.
	if len(extents) == 0 && bt.FextTreeOID != 0 {
		fextExtents, err := bt.fextFileExtents(reader, identifier)
		if err != nil {
			return nil, fmt.Errorf("unable to read file extents for OID %d from file extent tree: %w", identifier, err)
		}
		extents = fextExtents
	}

	return extents, nil
}

// fextFileExtents walks the file extent tree and returns every extent recorded
// for identifier, in logical-address order. Unlike the file-system tree, whose
// branch entries reference virtual OIDs resolved through the volume object map,
// this is a physical tree: branch entries hold the child's block number
// directly. Keys sort by (identifier, logical address).
func (bt *FileSystemBTree) fextFileExtents(
	reader io.ReaderAt,
	identifier uint64,
) ([]*FileExtent, error) {
	root, err := ReadBTreeNode(reader, bt.IOHandle, bt.EncryptionContext, bt.FextTreeOID)
	if err != nil {
		return nil, fmt.Errorf("unable to read file extent tree root at block %d: %w", bt.FextTreeOID, err)
	}

	extents := make([]*FileExtent, 0)

	var walk func(node *BTreeNode) error
	walk = func(node *BTreeNode) error {
		if node.IsLeafNode() {
			for _, entry := range node.Entries {
				entryID, logicalAddress, err := ParseFileExtentKey(entry.KeyData)
				if err != nil {
					continue
				}
				if entryID < identifier {
					continue
				}
				// Keys are sorted, so once the identifier moves past the one
				// being collected there is nothing further to find.
				if entryID > identifier {
					break
				}

				extent, err := parseFextExtentValue(entry.ValueData)
				if err != nil {
					return fmt.Errorf("unable to parse file extent value for OID %d: %w", entryID, err)
				}
				extent.LogicalOffset = logicalAddress
				extents = append(extents, extent)
			}
			return nil
		}

		for _, entry := range node.Entries {
			if len(entry.ValueData) < 8 {
				return fmt.Errorf("invalid file extent tree branch value size: %d", len(entry.ValueData))
			}
			// A physical tree's branch entry is the child block number itself.
			childBlock := binary.LittleEndian.Uint64(entry.ValueData[0:8])
			child, err := ReadBTreeNode(reader, bt.IOHandle, bt.EncryptionContext, childBlock)
			if err != nil {
				return fmt.Errorf("unable to read file extent tree node at block %d: %w", childBlock, err)
			}
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}

	if err := walk(root); err != nil {
		return nil, err
	}

	return extents, nil
}

// parseFextExtentValue decodes a file extent as stored in the file extent tree.
// That tree omits the trailing encryption id of a j_file_extent_val_t, leaving
// the length-and-flags word followed by the physical block number (16 bytes);
// accept the full 24-byte record too, in case a volume keeps the crypto id.
func parseFextExtentValue(data []byte) (*FileExtent, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("invalid file extent value size: expected at least 16 bytes, got %d", len(data))
	}

	extent := &FileExtent{
		DataSize:            binary.LittleEndian.Uint64(data[0:8]) & 0x00ffffffffffffff,
		PhysicalBlockNumber: binary.LittleEndian.Uint64(data[8:16]),
	}
	if len(data) >= 24 {
		extent.EncryptionIdentifier = binary.LittleEndian.Uint64(data[16:24])
	}
	return extent, nil
}

// AllRecordsForOID retrieves ALL file system records for a given OID
// Implements the algorithm from go-apfs GetFSRecordsForOid with descent and walk phases
func (bt *FileSystemBTree) AllRecordsForOID(
	reader io.ReaderAt,
	objectID uint64,
) ([]*BTreeEntry, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	rootNode, err := bt.RootNode(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to get root node: %w", err)
	}

	// Calculate tree height
	treeHeight := int(rootNode.NodeHeader.Level) + 1
	descPath := make([]int, treeHeight)

	records := make([]*BTreeEntry, 0)

	// PHASE 1: Descent - find first record with matching OID
	node := rootNode
	var firstLeafNode *BTreeNode
	for level := 0; level < treeHeight; level++ {
		if node.IsLeafNode() {
			firstLeafNode = node
			// Found leaf level - now position descPath at first matching record
			for idx, entry := range node.Entries {
				entryID, _ := ExtractIdentifierFromKey(entry.KeyData)
				if entryID == objectID {
					descPath[level] = idx
					break
				}
				if entryID > objectID {
					// No matching records exist
					return records, nil
				}
				descPath[level]++
			}
			break
		}

		// An index node must point somewhere, and one level down.
		if len(node.Entries) == 0 {
			return nil, fmt.Errorf("index node at level %d has no entries", node.NodeHeader.Level)
		}
		parentLevel := node.NodeHeader.Level

		// Find which child to descend
		foundChild := false
		for idx, entry := range node.Entries {
			entryID, _ := ExtractIdentifierFromKey(entry.KeyData)

			if entryID >= objectID {
				// Descend previous entry (or current if first)
				if idx > 0 {
					descPath[level] = idx - 1
				} else {
					descPath[level] = idx
				}

				childOID, err := bt.SubNodeOIDFromEntry(reader, node.Entries[descPath[level]])
				if err != nil {
					return nil, err
				}
				node, err = bt.SubNode(reader, childOID)
				if err != nil {
					return nil, err
				}
				foundChild = true
				break
			}
			descPath[level] = idx + 1
		}

		if !foundChild {
			// Descend last entry
			descPath[level] = len(node.Entries) - 1
			childOID, err := bt.SubNodeOIDFromEntry(reader, node.Entries[descPath[level]])
			if err != nil {
				return nil, err
			}
			node, err = bt.SubNode(reader, childOID)
			if err != nil {
				return nil, err
			}
		}
		if node.NodeHeader.Level+1 != parentLevel {
			return nil, fmt.Errorf("child of a level %d node is at level %d", parentLevel, node.NodeHeader.Level)
		}
	}
	if firstLeafNode == nil {
		return nil, fmt.Errorf("no leaf node within the tree's height of %d", treeHeight)
	}

	// FAST PATH: Check if all records are in the first leaf (common case)
	// Collect all matching records from first leaf
	leafLevel := treeHeight - 1
	allInFirstLeaf := true
	for idx := descPath[leafLevel]; idx < len(firstLeafNode.Entries); idx++ {
		entry := firstLeafNode.Entries[idx]
		entryID, err := ExtractIdentifierFromKey(entry.KeyData)
		if err != nil {
			continue
		}
		if entryID != objectID {
			// Hit end of matching records
			return records, nil
		}
		records = append(records, entry)
		descPath[leafLevel]++
	}

	// If we exhausted the leaf, check if there might be more in next leaf
	if descPath[leafLevel] >= len(firstLeafNode.Entries) {
		allInFirstLeaf = false
	}

	// If all records were in first leaf, we're done (common case)
	if allInFirstLeaf {
		return records, nil
	}

	// PHASE 2: Walk - collect remaining records from subsequent leaves (rare)
	if treeHeight == 1 {
		// The root is the only leaf; there is no next leaf to walk to
		return records, nil
	}

	for {
		// The current leaf is exhausted: advance to the next leaf by bumping
		// the lowest interior level and resetting everything below it
		descPath[leafLevel-1]++
		descPath[leafLevel] = 0

		// Re-descend from root using descPath, bubbling exhaustion upward
		node = rootNode
		level := 0
		for level < leafLevel {
			if descPath[level] >= len(node.Entries) {
				if level == 0 {
					// Root exhausted - whole tree walked
					return records, nil
				}
				// This interior node is exhausted: bump its parent, reset
				// this level and below, and restart the descent from root
				descPath[level-1]++
				for j := level; j < treeHeight; j++ {
					descPath[j] = 0
				}
				node = rootNode
				level = 0
				continue
			}

			childOID, err := bt.SubNodeOIDFromEntry(reader, node.Entries[descPath[level]])
			if err != nil {
				return nil, err
			}
			node, err = bt.SubNode(reader, childOID)
			if err != nil {
				return nil, err
			}
			level++
		}

		if !node.IsLeafNode() {
			return nil, fmt.Errorf("B-tree walk reached level %d without finding a leaf node", level)
		}

		// At leaf node - collect matching records
		for idx := descPath[leafLevel]; idx < len(node.Entries); idx++ {
			entry := node.Entries[idx]
			entryID, err := ExtractIdentifierFromKey(entry.KeyData)
			if err != nil {
				continue
			}

			if entryID != objectID {
				// No more matching records
				return records, nil
			}

			records = append(records, entry)
			descPath[leafLevel]++
		}
		// Exhausted this leaf too, continue to the next one
	}
}

// InodeByIdentifier retrieves an inode by identifier
func (bt *FileSystemBTree) InodeByIdentifier(
	reader io.ReaderAt,
	identifier uint64,
	xid uint64,
) (*Inode, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	if DebugOutput {
		fmt.Printf("GetInodeByIdentifier: searching for inode %d\n", identifier)
	}

	// Use comprehensive tree traversal to get ALL records for this OID
	allRecords, err := bt.AllRecordsForOID(reader, identifier)
	if err != nil {
		return nil, fmt.Errorf("unable to get records for OID %d: %w", identifier, err)
	}

	if DebugOutput {
		fmt.Printf("GetInodeByIdentifier: found %d total records for inode %d\n", len(allRecords), identifier)
	}

	// Find the inode entry
	for _, entry := range allRecords {
		// Check if this entry is an inode
		dataType, err := ExtractDataTypeFromKey(entry.KeyData)
		if err != nil {
			continue
		}

		if dataType != FileSystemRecordTypeInode {
			continue
		}

		entryID, err := ExtractIdentifierFromKey(entry.KeyData)
		if err != nil {
			continue
		}

		if entryID == identifier {
			// Found the inode - parse it
			inode, err := NewInode()
			if err != nil {
				return nil, fmt.Errorf("unable to create inode: %w", err)
			}

			if err := inode.ReadKeyData(entry.KeyData); err != nil {
				return nil, fmt.Errorf("unable to parse inode key: %w", err)
			}

			if err := inode.ReadValueData(entry.ValueData); err != nil {
				return nil, fmt.Errorf("unable to parse inode value: %w", err)
			}

			return inode, nil
		}

		// NOTE: Do NOT break early based on entryID > identifier
		// B-tree entries are sorted by (type, id) not just (id)
		// so we must check all entries in the leaf node
	}

	return nil, fmt.Errorf("inode not found: %d", identifier)
}

// DirectoryEntries retrieves directory entries for a parent identifier
func (bt *FileSystemBTree) DirectoryEntries(
	reader io.ReaderAt,
	parentIdentifier uint64,
	xid uint64,
) ([]*DirectoryEntryRecord, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	// Directory records for one parent can span many leaf nodes; use the
	// full multi-leaf traversal and filter for directory entry records
	allRecords, err := bt.AllRecordsForOID(reader, parentIdentifier)
	if err != nil {
		return nil, fmt.Errorf("unable to get records for OID %d: %w", parentIdentifier, err)
	}

	entries := make([]*DirectoryEntryRecord, 0)

	for _, entry := range allRecords {
		dataType, err := ExtractDataTypeFromKey(entry.KeyData)
		if err != nil {
			continue
		}

		if dataType != FileSystemRecordTypeDirectoryEntry {
			continue
		}

		dirRecord := NewDirectoryEntryRecord()

		if err := dirRecord.ReadKeyData(entry.KeyData); err != nil {
			return nil, fmt.Errorf("unable to parse directory entry record key: %w", err)
		}

		if err := dirRecord.ReadValueData(entry.ValueData); err != nil {
			return nil, fmt.Errorf("unable to parse directory entry record value: %w", err)
		}

		entries = append(entries, dirRecord)
	}

	return entries, nil
}

// Attributes retrieves extended attributes for an identifier
func (bt *FileSystemBTree) Attributes(
	reader io.ReaderAt,
	identifier uint64,
	xid uint64,
) ([]*AttributeValues, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	// Extended attributes for one file can span leaf nodes; use the full
	// multi-leaf traversal and filter for extended attribute records
	allRecords, err := bt.AllRecordsForOID(reader, identifier)
	if err != nil {
		return nil, fmt.Errorf("unable to get records for OID %d: %w", identifier, err)
	}

	attributes := make([]*AttributeValues, 0)

	for _, entry := range allRecords {
		dataType, err := ExtractDataTypeFromKey(entry.KeyData)
		if err != nil {
			continue
		}

		if dataType != FileSystemRecordTypeExtendedAttribute {
			continue
		}

		attr := &AttributeValues{}

		if err := attr.ReadKeyData(entry.KeyData); err != nil {
			return nil, fmt.Errorf("unable to parse attribute key: %w", err)
		}

		if err := attr.ReadValueData(entry.ValueData); err != nil {
			return nil, fmt.Errorf("unable to parse attribute value: %w", err)
		}

		attributes = append(attributes, attr)
	}

	return attributes, nil
}

// EntryFromNodeByIdentifier retrieves an entry from a node by identifier and data type
func (bt *FileSystemBTree) EntryFromNodeByIdentifier(
	node *BTreeNode,
	identifier uint64,
	dataType uint8,
) (*BTreeEntry, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	if node == nil {
		return nil, fmt.Errorf("invalid node")
	}

	if DebugOutput {
		fmt.Printf("FileSystemBTree.EntryFromNodeByIdentifier: retrieving B-tree entry identifier: %d, data type: 0x%02x\n",
			identifier, dataType)
	}

	// Create lookup identifier (data type in upper 4 bits + identifier in lower 60 bits)
	lookupIdentifier := (uint64(dataType) << 60) | identifier

	// Search through entries
	var previousEntry *BTreeEntry
	for _, entry := range node.Entries {
		// Extract file system identifier from key
		if len(entry.KeyData) < 8 {
			continue
		}

		fsIdentifier := binary.LittleEndian.Uint64(entry.KeyData[0:8])
		entryIdentifier := fsIdentifier & 0x0FFFFFFFFFFFFFFF // Lower 60 bits
		entryDataType := uint8((fsIdentifier >> 60) & 0x0F)  // Upper 4 bits

		if node.IsLeafNode() {
			// In leaf node, exact match
			if entryIdentifier == identifier && (dataType == FileSystemRecordTypeAny || entryDataType == dataType) {
				return entry, nil
			}
		} else {
			// In branch node, find the entry where lookupIdentifier <= fsIdentifier
			if lookupIdentifier <= fsIdentifier {
				if previousEntry != nil {
					return previousEntry, nil
				}
				return entry, nil
			}
			previousEntry = entry
		}
	}

	// If we're in a branch node and didn't find a match, return the last entry
	if !node.IsLeafNode() && previousEntry != nil {
		return previousEntry, nil
	}

	return nil, fmt.Errorf("entry not found for identifier: %d, data type: 0x%02x", identifier, dataType)
}

// EntryByIdentifier retrieves an entry by identifier and data type, navigating the tree
func (bt *FileSystemBTree) EntryByIdentifier(
	reader io.ReaderAt,
	identifier uint64,
	dataType uint8,
	xid uint64,
) (*BTreeNode, *BTreeEntry, error) {
	if bt == nil {
		return nil, nil, fmt.Errorf("invalid file system B-tree")
	}

	// Get root node
	node, err := bt.RootNode(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read root node: %w", err)
	}

	// Navigate to the correct node
	for !node.IsLeafNode() {
		entry, err := bt.EntryFromNodeByIdentifier(node, identifier, dataType)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get entry from node: %w", err)
		}

		// Get child block number
		childBlockNumber, err := bt.SubNodeOIDFromEntry(reader, entry)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get child block number: %w", err)
		}

		// Read child node
		node, err = bt.SubNode(reader, childBlockNumber)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to read sub-node: %w", err)
		}
	}

	// Now we're at the leaf node, get the entry
	entry, err := bt.EntryFromNodeByIdentifier(node, identifier, dataType)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get entry from leaf node: %w", err)
	}

	return node, entry, nil
}

// DirectoryEntryRecordByUTF8Name retrieves a directory entry record by UTF-8 name
func (bt *FileSystemBTree) DirectoryEntryRecordByUTF8Name(
	reader io.ReaderAt,
	parentIdentifier uint64,
	name string,
	xid uint64,
) (*DirectoryEntryRecord, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	if name == "" {
		return nil, fmt.Errorf("invalid name")
	}

	if err := ValidateLookupName(name); err != nil {
		return nil, fmt.Errorf("invalid directory lookup name: %w", err)
	}

	nameHash := CalculateNameHash([]byte(name), bt.UseCaseFolding)
	index, err := bt.directoryIndex(reader, parentIdentifier)
	if err != nil {
		return nil, err
	}
	for _, dirRecord := range index[nameHash] {
		if dirRecord.CompareNameWithUTF8String([]byte(name), nameHash, bt.UseCaseFolding) == 0 {
			found := *dirRecord
			return &found, nil
		}
	}
	return nil, fmt.Errorf("directory entry record not found")
}

// dirIndexCapacity is how many directories' indexes are kept.
const dirIndexCapacity = 32

type dirIndexEntry struct {
	parent uint64
	byHash map[uint32][]*DirectoryEntryRecord
}

// directoryIndex returns a directory's entries grouped by name hash.
//
// A directory's records can span many leaf nodes, and finding one name used to
// read and parse all of them, so opening each of a directory's n files cost
// O(n) and opening them all O(n^2): 400us per open in a directory of 20,000.
// The index is built from one such read and reused while the directory stays
// among the most recently used, which is what a walk that lists a directory
// and then opens its entries needs.
func (bt *FileSystemBTree) directoryIndex(reader io.ReaderAt, parent uint64) (map[uint32][]*DirectoryEntryRecord, error) {
	bt.dirIndexMu.Lock()
	if el, ok := bt.dirIndexes[parent]; ok {
		bt.dirIndexLRU.MoveToFront(el)
		index := el.Value.(*dirIndexEntry).byHash
		bt.dirIndexMu.Unlock()
		return index, nil
	}
	bt.dirIndexMu.Unlock()

	records, err := bt.AllRecordsForOID(reader, parent)
	if err != nil {
		return nil, fmt.Errorf("unable to get records for OID %d: %w", parent, err)
	}
	index := make(map[uint32][]*DirectoryEntryRecord)
	for _, entry := range records {
		dataType, err := ExtractDataTypeFromKey(entry.KeyData)
		if err != nil || dataType != FileSystemRecordTypeDirectoryEntry {
			continue
		}
		dirRecord := NewDirectoryEntryRecord()
		if err := dirRecord.ReadKeyData(entry.KeyData); err != nil {
			continue
		}
		if err := dirRecord.ReadValueData(entry.ValueData); err != nil {
			continue
		}
		index[dirRecord.NameHash] = append(index[dirRecord.NameHash], dirRecord)
	}

	bt.dirIndexMu.Lock()
	defer bt.dirIndexMu.Unlock()
	if bt.dirIndexes == nil {
		bt.dirIndexes = make(map[uint64]*list.Element)
		bt.dirIndexLRU = list.New()
	}
	if el, ok := bt.dirIndexes[parent]; ok {
		// Built concurrently by another caller; keep theirs.
		bt.dirIndexLRU.MoveToFront(el)
		return el.Value.(*dirIndexEntry).byHash, nil
	}
	bt.dirIndexes[parent] = bt.dirIndexLRU.PushFront(&dirIndexEntry{parent: parent, byHash: index})
	if bt.dirIndexLRU.Len() > dirIndexCapacity {
		oldest := bt.dirIndexLRU.Back()
		bt.dirIndexLRU.Remove(oldest)
		delete(bt.dirIndexes, oldest.Value.(*dirIndexEntry).parent)
	}
	return index, nil
}

// DirectoryEntryRecordByUTF16Name retrieves a directory entry record by UTF-16 name
func (bt *FileSystemBTree) DirectoryEntryRecordByUTF16Name(
	reader io.ReaderAt,
	parentIdentifier uint64,
	name []uint16,
	xid uint64,
) (*DirectoryEntryRecord, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	if len(name) == 0 {
		return nil, fmt.Errorf("invalid name")
	}

	// Convert UTF-16 to UTF-8 and delegate to the multi-leaf UTF-8 search
	utf8Name := UTF16ToString(name)

	return bt.DirectoryEntryRecordByUTF8Name(reader, parentIdentifier, utf8Name, xid)
}

// InodeByUTF8Name retrieves an inode and directory entry record by UTF-8 name
func (bt *FileSystemBTree) InodeByUTF8Name(
	reader io.ReaderAt,
	parentIdentifier uint64,
	name string,
	xid uint64,
) (*Inode, *DirectoryEntryRecord, error) {
	if bt == nil {
		return nil, nil, fmt.Errorf("invalid file system B-tree")
	}

	// First get the directory entry record
	dirRecord, err := bt.DirectoryEntryRecordByUTF8Name(reader, parentIdentifier, name, xid)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get directory entry record: %w", err)
	}

	// Then get the inode using the identifier from the directory entry record
	inode, err := bt.InodeByIdentifier(reader, dirRecord.Identifier, xid)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get inode: %w", err)
	}

	return inode, dirRecord, nil
}

// InodeByUTF8Path retrieves an inode and directory entry record by UTF-8 path
func (bt *FileSystemBTree) InodeByUTF8Path(
	reader io.ReaderAt,
	parentIdentifier uint64,
	path string,
	xid uint64,
) (*Inode, *DirectoryEntryRecord, error) {
	if bt == nil {
		return nil, nil, fmt.Errorf("invalid file system B-tree")
	}

	if path == "" {
		return nil, nil, fmt.Errorf("invalid path")
	}

	// Split path by '/'
	pathSegments := splitPath(path)

	currentParentID := parentIdentifier
	var currentInode *Inode
	var currentDirRecord *DirectoryEntryRecord
	var err error

	// Navigate through each path segment
	for _, segment := range pathSegments {
		if segment == "" {
			continue
		}

		currentInode, currentDirRecord, err = bt.InodeByUTF8Name(reader, currentParentID, segment, xid)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get inode for path segment '%s': %w", segment, err)
		}

		// Update parent ID for next iteration
		currentParentID = currentDirRecord.Identifier
	}

	return currentInode, currentDirRecord, nil
}

// InodeByUTF16Name retrieves an inode and directory entry record by UTF-16 name
func (bt *FileSystemBTree) InodeByUTF16Name(
	reader io.ReaderAt,
	parentIdentifier uint64,
	name []uint16,
	xid uint64,
) (*Inode, *DirectoryEntryRecord, error) {
	if bt == nil {
		return nil, nil, fmt.Errorf("invalid file system B-tree")
	}

	// First get the directory entry record
	dirRecord, err := bt.DirectoryEntryRecordByUTF16Name(reader, parentIdentifier, name, xid)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get directory entry record: %w", err)
	}

	// Then get the inode using the identifier from the directory entry record
	inode, err := bt.InodeByIdentifier(reader, dirRecord.Identifier, xid)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get inode: %w", err)
	}

	return inode, dirRecord, nil
}

// InodeByUTF16Path retrieves an inode and directory entry record by UTF-16 path
func (bt *FileSystemBTree) InodeByUTF16Path(
	reader io.ReaderAt,
	parentIdentifier uint64,
	path []uint16,
	xid uint64,
) (*Inode, *DirectoryEntryRecord, error) {
	if bt == nil {
		return nil, nil, fmt.Errorf("invalid file system B-tree")
	}

	// Convert UTF-16 path to UTF-8
	utf8Path := UTF16ToString(path)

	// Use UTF-8 path function
	return bt.InodeByUTF8Path(reader, parentIdentifier, utf8Path, xid)
}

// splitPath splits a path string by '/' separator
func splitPath(path string) []string {
	segments := []string{}
	currentSegment := ""

	for _, char := range path {
		if char == '/' {
			if currentSegment != "" {
				segments = append(segments, currentSegment)
				currentSegment = ""
			}
		} else {
			currentSegment += string(char)
		}
	}

	if currentSegment != "" {
		segments = append(segments, currentSegment)
	}

	return segments
}
