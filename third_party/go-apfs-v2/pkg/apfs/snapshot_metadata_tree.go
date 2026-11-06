// Snapshot metadata tree functions
package apfs

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// SnapshotMetadataTree represents the APFS snapshot metadata B-tree
type SnapshotMetadataTree struct {
	IOHandle       *IOHandle
	ObjectMapBTree *ObjectMapBTree
	RootNodeOID    uint64
	nodeCache      map[uint64]*BTreeNode
}

// NewSnapshotMetadataTree creates a new snapshot metadata tree
func NewSnapshotMetadataTree(
	ioHandle *IOHandle,
	objectMapBTree *ObjectMapBTree,
	rootNodeOID uint64,
) (*SnapshotMetadataTree, error) {
	if ioHandle == nil {
		return nil, fmt.Errorf("invalid IO handle")
	}

	if objectMapBTree == nil {
		return nil, fmt.Errorf("invalid object map B-tree")
	}

	return &SnapshotMetadataTree{
		IOHandle:       ioHandle,
		ObjectMapBTree: objectMapBTree,
		RootNodeOID:    rootNodeOID,
		nodeCache:      make(map[uint64]*BTreeNode),
	}, nil
}

// Close releases resources associated with the snapshot metadata tree
func (t *SnapshotMetadataTree) Close() error {
	if t == nil {
		return fmt.Errorf("invalid snapshot metadata tree")
	}

	// Clear the node cache
	t.nodeCache = nil

	return nil
}

// SubNodeOIDFromEntry retrieves the sub node block number from a B-tree entry
func (t *SnapshotMetadataTree) SubNodeOIDFromEntry(
	reader io.ReaderAt,
	entry *BTreeEntry,
	xid uint64,
) (uint64, error) {
	if t == nil {
		return 0, fmt.Errorf("invalid snapshot metadata tree")
	}

	if entry == nil {
		return 0, fmt.Errorf("invalid B-tree entry")
	}

	if len(entry.ValueData) != 8 {
		return 0, fmt.Errorf("invalid B-tree entry - unsupported value data size")
	}

	// Parse sub node object identifier
	subNodeObjectIdentifier := binary.LittleEndian.Uint64(entry.ValueData)

	if isVerbose() {
		notifyPrintf("%s: sub node object identifier: %d (transaction: %d)\n",
			"SubNodeOIDFromEntry", subNodeObjectIdentifier, xid)
	}

	// Get the physical block number from the object map
	descriptor, err := t.ObjectMapBTree.DescriptorByObjectIdentifier(
		reader,
		subNodeObjectIdentifier,
		xid,
	)
	if err != nil {
		return 0, fmt.Errorf("unable to retrieve object map descriptor for sub node object identifier: %d (transaction: %d): %w",
			subNodeObjectIdentifier, xid, err)
	}

	if descriptor == nil {
		return 0, nil
	}

	physicalAddress, err := descriptor.PhysicalAddress()
	if err != nil {
		return 0, fmt.Errorf("unable to get physical address: %w", err)
	}

	if isVerbose() {
		notifyPrintf("%s: sub node block number: %d\n", "SubNodeOIDFromEntry", physicalAddress)
	}

	return physicalAddress, nil
}

// RootNode retrieves the snapshot metadata tree root node
func (t *SnapshotMetadataTree) RootNode(
	reader io.ReaderAt,
	rootNodeOID uint64,
) (*BTreeNode, error) {
	if t == nil {
		return nil, fmt.Errorf("invalid snapshot metadata tree")
	}

	if rootNodeOID > common.Int32Max {
		return nil, fmt.Errorf("invalid root node block number value out of bounds")
	}

	// Check cache first
	if node, found := t.nodeCache[rootNodeOID]; found {
		return node, nil
	}

	// Start profiling if enabled
	var startTimestamp int64
	if t.IOHandle.Profiler != nil {
		var err error
		startTimestamp, err = t.IOHandle.Profiler.StartTiming()
		if err != nil {
			return nil, fmt.Errorf("unable to start timing: %w", err)
		}
	}

	// Read the block data
	blockOffset := int64(rootNodeOID) * int64(t.IOHandle.BlockSize)
	blockData := make([]byte, t.IOHandle.BlockSize)
	n, err := reader.ReadAt(blockData, blockOffset)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("unable to read data block: %d: %w", rootNodeOID, err)
	}
	if n != int(t.IOHandle.BlockSize) {
		return nil, fmt.Errorf("unable to read data block: %d", rootNodeOID)
	}

	// Parse the B-tree node
	node := NewBTreeNode()

	if err := node.ReadData(blockData); err != nil {
		return nil, fmt.Errorf("unable to read B-tree node: %w", err)
	}

	// Validate object type and subtype
	if node.ObjectType != 0x40000002 {
		return nil, fmt.Errorf("invalid object type: 0x%08x", node.ObjectType)
	}

	if node.ObjectSubtype != 0x00000010 {
		return nil, fmt.Errorf("invalid object subtype: 0x%08x", node.ObjectSubtype)
	}

	// Validate node is a root node
	if node.NodeHeader == nil {
		return nil, fmt.Errorf("invalid B-tree node - missing node header")
	}

	if (node.NodeHeader.Flags & 0x0001) == 0 {
		return nil, fmt.Errorf("unsupported flags: 0x%04x", node.NodeHeader.Flags)
	}

	// Validate footer
	if node.Info == nil {
		return nil, fmt.Errorf("invalid B-tree node - missing footer")
	}

	if node.Info.NodeSize != 4096 {
		return nil, fmt.Errorf("invalid node size value out of bounds")
	}

	if node.Info.KeySize != 0 {
		return nil, fmt.Errorf("invalid key size value out of bounds")
	}

	if node.Info.ValueSize != 0 {
		return nil, fmt.Errorf("invalid value size value out of bounds")
	}

	// Cache the node
	t.nodeCache[rootNodeOID] = node

	// Stop profiling if enabled
	if t.IOHandle.Profiler != nil {
		if err := t.IOHandle.Profiler.StopTiming(
			startTimestamp,
			"GetRootNode",
			blockOffset,
			uint64(t.IOHandle.BlockSize),
		); err != nil {
			return nil, fmt.Errorf("unable to stop timing: %w", err)
		}
	}

	return node, nil
}

// SubNode retrieves a snapshot metadata tree sub node
func (t *SnapshotMetadataTree) SubNode(
	reader io.ReaderAt,
	subNodeOID uint64,
) (*BTreeNode, error) {
	if t == nil {
		return nil, fmt.Errorf("invalid snapshot metadata tree")
	}

	if subNodeOID > common.Int32Max {
		return nil, fmt.Errorf("invalid sub node block number value out of bounds")
	}

	// Check cache first
	if node, found := t.nodeCache[subNodeOID]; found {
		return node, nil
	}

	// Start profiling if enabled
	var startTimestamp int64
	if t.IOHandle.Profiler != nil {
		var err error
		startTimestamp, err = t.IOHandle.Profiler.StartTiming()
		if err != nil {
			return nil, fmt.Errorf("unable to start timing: %w", err)
		}
	}

	// Read the block data
	blockOffset := int64(subNodeOID) * int64(t.IOHandle.BlockSize)
	blockData := make([]byte, t.IOHandle.BlockSize)
	n, err := reader.ReadAt(blockData, blockOffset)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("unable to read data block: %d: %w", subNodeOID, err)
	}
	if n != int(t.IOHandle.BlockSize) {
		return nil, fmt.Errorf("unable to read data block: %d", subNodeOID)
	}

	// Parse the B-tree node
	node := NewBTreeNode()

	if err := node.ReadData(blockData); err != nil {
		return nil, fmt.Errorf("unable to read B-tree node: %w", err)
	}

	// Validate object type and subtype
	if node.ObjectType != 0x40000002 {
		return nil, fmt.Errorf("invalid object type: 0x%08x", node.ObjectType)
	}

	if node.ObjectSubtype != 0x00000010 {
		return nil, fmt.Errorf("invalid object subtype: 0x%08x", node.ObjectSubtype)
	}

	// Validate footer
	if node.Info == nil {
		return nil, fmt.Errorf("invalid B-tree node - missing footer")
	}

	if node.Info.NodeSize != 4096 {
		return nil, fmt.Errorf("invalid node size value out of bounds")
	}

	// Cache the node
	t.nodeCache[subNodeOID] = node

	// Stop profiling if enabled
	if t.IOHandle.Profiler != nil {
		if err := t.IOHandle.Profiler.StopTiming(
			startTimestamp,
			"GetSubNode",
			blockOffset,
			uint64(t.IOHandle.BlockSize),
		); err != nil {
			return nil, fmt.Errorf("unable to stop timing: %w", err)
		}
	}

	return node, nil
}

// EntryFromNodeByIdentifier retrieves a B-tree entry from a node by object identifier
func (t *SnapshotMetadataTree) EntryFromNodeByIdentifier(
	node *BTreeNode,
	oid uint64,
) (*BTreeEntry, error) {
	if t == nil {
		return nil, fmt.Errorf("invalid snapshot metadata tree")
	}

	if node == nil {
		return nil, fmt.Errorf("invalid B-tree node")
	}

	if node.Entries == nil {
		return nil, fmt.Errorf("invalid B-tree node - missing entries")
	}

	// Binary search for the entry
	for _, entry := range node.Entries {
		if len(entry.KeyData) < 8 {
			continue
		}

		entryObjectIdentifier := binary.LittleEndian.Uint64(entry.KeyData[0:8])

		if entryObjectIdentifier == oid {
			return entry, nil
		}
	}

	return nil, nil
}

// EntryByIdentifier retrieves a B-tree entry by object identifier
func (t *SnapshotMetadataTree) EntryByIdentifier(
	reader io.ReaderAt,
	oid uint64,
) (*BTreeNode, *BTreeEntry, error) {
	if t == nil {
		return nil, nil, fmt.Errorf("invalid snapshot metadata tree")
	}

	// Get the root node
	node, err := t.RootNode(reader, t.RootNodeOID)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get root node: %w", err)
	}

	// Traverse the tree
	for {
		if node == nil {
			return nil, nil, fmt.Errorf("invalid B-tree node")
		}

		// Check if this is a leaf node
		isLeaf := node.NodeHeader != nil && (node.NodeHeader.Flags&0x0002) != 0

		if isLeaf {
			// Search for the entry in the leaf node
			entry, err := t.EntryFromNodeByIdentifier(node, oid)
			if err != nil {
				return nil, nil, fmt.Errorf("unable to get entry from node: %w", err)
			}
			return node, entry, nil
		}

		// Branch node - find the appropriate sub node
		var subNodeOID uint64
		found := false

		for _, entry := range node.Entries {
			if len(entry.KeyData) < 8 {
				continue
			}

			entryObjectIdentifier := binary.LittleEndian.Uint64(entry.KeyData[0:8])

			if oid <= entryObjectIdentifier {
				// Get sub node block number
				subNodeOID, err = t.SubNodeOIDFromEntry(reader, entry, 0)
				if err != nil {
					return nil, nil, fmt.Errorf("unable to get sub node block number: %w", err)
				}
				found = true
				break
			}
		}

		if !found {
			// Not found
			return nil, nil, nil
		}

		// Get the sub node
		node, err = t.SubNode(reader, subNodeOID)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get sub node: %w", err)
		}
	}
}

// SnapshotMetadata represents snapshot metadata
type SnapshotMetadata struct {
	// The transaction identifier of the snapshot. This is the object
	// identifier half of the snapshot metadata record's key (j_key_t.obj_id),
	// which for snapshot metadata records holds an xid rather than an oid.
	XID uint64
	// The physical object identifier of the snapshot's volume superblock
	// (j_snap_metadata_val_t.sblock_oid).
	VolumeSuperblockOID uint64
	// The physical object identifier of the snapshot's extentref tree
	// (j_snap_metadata_val_t.extentref_tree_oid).
	ExtentrefTreeOID uint64
	// Creation time, in nanoseconds since 1970-01-01 UTC (create_time).
	CreationTime uint64
	// Last-modified time, in nanoseconds since 1970-01-01 UTC (change_time).
	ChangeTime uint64
	Name       string
}

// MetadataByObjectIdentifier retrieves snapshot metadata by object identifier
func (t *SnapshotMetadataTree) MetadataByObjectIdentifier(
	reader io.ReaderAt,
	oid uint64,
) (*SnapshotMetadata, error) {
	if t == nil {
		return nil, fmt.Errorf("invalid snapshot metadata tree")
	}

	// Get the entry
	_, entry, err := t.EntryByIdentifier(reader, oid)
	if err != nil {
		return nil, fmt.Errorf("unable to get entry by identifier: %w", err)
	}

	if entry == nil {
		return nil, nil
	}

	// Parse the metadata
	metadata := &SnapshotMetadata{
		XID: oid,
	}

	// Parse value data
	if len(entry.ValueData) >= 46 {
		metadata.VolumeSuperblockOID = binary.LittleEndian.Uint64(entry.ValueData[8:16])

		// Parse name
		nameSize := binary.LittleEndian.Uint16(entry.ValueData[44:46])
		if len(entry.ValueData) >= 46+int(nameSize) {
			metadata.Name = string(entry.ValueData[46 : 46+nameSize])
		}
	}

	return metadata, nil
}

// Snapshots retrieves all snapshots from the tree
func (t *SnapshotMetadataTree) Snapshots(
	reader io.ReaderAt,
	xid uint64,
) ([]*SnapshotMetadata, error) {
	if t == nil {
		return nil, fmt.Errorf("invalid snapshot metadata tree")
	}

	// Get the root node
	node, err := t.RootNode(reader, t.RootNodeOID)
	if err != nil {
		return nil, fmt.Errorf("unable to get root node: %w", err)
	}

	// Initialize snapshots array
	snapshots := make([]*SnapshotMetadata, 0)

	// Check if this is a leaf node
	isLeaf := node.NodeHeader != nil && (node.NodeHeader.Flags&0x0002) != 0

	if isLeaf {
		// Get snapshots from leaf node
		if err := t.getSnapshotsFromLeafNode(node, &snapshots); err != nil {
			return nil, fmt.Errorf("unable to get snapshots from leaf node: %w", err)
		}
	} else {
		// Get snapshots from branch node
		if err := t.getSnapshotsFromBranchNode(reader, node, xid, &snapshots, 0); err != nil {
			return nil, fmt.Errorf("unable to get snapshots from branch node: %w", err)
		}
	}

	return snapshots, nil
}

// getSnapshotsFromLeafNode retrieves snapshots from a leaf node
func (t *SnapshotMetadataTree) getSnapshotsFromLeafNode(
	node *BTreeNode,
	snapshots *[]*SnapshotMetadata,
) error {
	if t == nil {
		return fmt.Errorf("invalid snapshot metadata tree")
	}

	if node == nil {
		return fmt.Errorf("invalid B-tree node")
	}

	if snapshots == nil {
		return fmt.Errorf("invalid snapshots array")
	}

	// The snapshot metadata tree holds two record kinds keyed by object type in
	// the high 4 bits of obj_id_and_type: APFS_TYPE_SNAP_METADATA (1), whose key
	// object id is the snapshot's transaction id and whose value is a
	// j_snap_metadata_val; and APFS_TYPE_SNAP_NAME (11), a name->xid index. Only
	// the metadata records represent snapshots.
	const (
		objIDMask         = 0x0fffffffffffffff
		objTypeShift      = 60
		typeSnapMetadata  = 1
		snapMetaValFixed  = 50 // extentref_oid..name_len, then name
		snapMetaNameLenAt = 48
	)
	for _, entry := range node.Entries {
		if len(entry.KeyData) < 8 {
			continue
		}
		objIDAndType := binary.LittleEndian.Uint64(entry.KeyData[0:8])
		if objIDAndType>>objTypeShift != typeSnapMetadata {
			continue // skip snapshot-name records
		}

		metadata := &SnapshotMetadata{
			XID: objIDAndType & objIDMask,
		}

		v := entry.ValueData
		if len(v) >= snapMetaValFixed {
			metadata.ExtentrefTreeOID = binary.LittleEndian.Uint64(v[0:8])
			metadata.VolumeSuperblockOID = binary.LittleEndian.Uint64(v[8:16])
			metadata.CreationTime = binary.LittleEndian.Uint64(v[16:24])
			metadata.ChangeTime = binary.LittleEndian.Uint64(v[24:32])

			nameSize := binary.LittleEndian.Uint16(v[snapMetaNameLenAt : snapMetaNameLenAt+2])
			if nameSize > 0 && len(v) >= snapMetaValFixed+int(nameSize) {
				// name is NUL-terminated; drop the trailing NUL.
				metadata.Name = string(v[snapMetaValFixed : snapMetaValFixed+int(nameSize)-1])
			}
		}

		*snapshots = append(*snapshots, metadata)
	}

	return nil
}

// NumberOfEntries retrieves the number of snapshot entries in the tree
func (t *SnapshotMetadataTree) NumberOfEntries(reader io.ReaderAt) (int, error) {
	if t == nil {
		return 0, fmt.Errorf("invalid snapshot metadata tree")
	}

	// Get all snapshots
	snapshots, err := t.Snapshots(reader, 0)
	if err != nil {
		return 0, fmt.Errorf("unable to get snapshots: %w", err)
	}

	return len(snapshots), nil
}

// EntryByIndex retrieves a snapshot metadata entry by index
func (t *SnapshotMetadataTree) EntryByIndex(reader io.ReaderAt, index int) (*SnapshotMetadata, error) {
	if t == nil {
		return nil, fmt.Errorf("invalid snapshot metadata tree")
	}

	// Get all snapshots
	snapshots, err := t.Snapshots(reader, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to get snapshots: %w", err)
	}

	if index < 0 || index >= len(snapshots) {
		return nil, fmt.Errorf("index %d out of range (0-%d)", index, len(snapshots)-1)
	}

	return snapshots[index], nil
}

// getSnapshotsFromBranchNode retrieves snapshots from a branch node (recursive)
func (t *SnapshotMetadataTree) getSnapshotsFromBranchNode(
	reader io.ReaderAt,
	node *BTreeNode,
	xid uint64,
	snapshots *[]*SnapshotMetadata,
	recursionDepth int,
) error {
	if t == nil {
		return fmt.Errorf("invalid snapshot metadata tree")
	}

	if node == nil {
		return fmt.Errorf("invalid B-tree node")
	}

	if snapshots == nil {
		return fmt.Errorf("invalid snapshots array")
	}

	if recursionDepth > MaxBTreeNodeDepth {
		return fmt.Errorf("maximum recursion depth exceeded")
	}

	// Iterate through all entries in the branch node
	for _, entry := range node.Entries {
		// Get sub node block number
		subNodeOID, err := t.SubNodeOIDFromEntry(reader, entry, xid)
		if err != nil {
			return fmt.Errorf("unable to get sub node block number: %w", err)
		}

		if subNodeOID == 0 {
			continue
		}

		// Get the sub node
		subNode, err := t.SubNode(reader, subNodeOID)
		if err != nil {
			return fmt.Errorf("unable to get sub node: %w", err)
		}

		// Check if this is a leaf node
		isLeaf := subNode.NodeHeader != nil && (subNode.NodeHeader.Flags&0x0002) != 0

		if isLeaf {
			// Get snapshots from leaf node
			if err := t.getSnapshotsFromLeafNode(subNode, snapshots); err != nil {
				return fmt.Errorf("unable to get snapshots from leaf node: %w", err)
			}
		} else {
			// Recursively get snapshots from branch node
			if err := t.getSnapshotsFromBranchNode(reader, subNode, xid, snapshots, recursionDepth+1); err != nil {
				return fmt.Errorf("unable to get snapshots from branch node: %w", err)
			}
		}
	}

	return nil
}
