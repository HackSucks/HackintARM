// Object map B-tree functions
package apfs

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// Object types for object map B-tree nodes
	ObjectMapBTreeRootNodeType = 0x40000002 // OBJECT_TYPE_BTREE
	ObjectMapBTreeSubNodeType  = 0x40000003 // OBJECT_TYPE_BTREE_NODE

	// Object subtype for object map B-tree
	ObjectMapBTreeSubtype = 0x0000000b // OBJECT_SUBTYPE_OMAP

	// B-tree node flags
	BTreeNodeFlagRoot           = 0x0001
	BTreeNodeFlagLeaf           = 0x0002
	BTreeNodeFlagFixedKVSize    = 0x0004
	BTreeNodeFlagHashed         = 0x0008
	BTreeNodeFlagNoHeader       = 0x0010
	BTreeNodeFlagCheckKOffInval = 0x8000

	// Maximum B-tree recursion depth
	MaxObjectMapBTreeDepth = 32

	// Object map B-tree key and value sizes
	ObjectMapBTreeKeySize   = 16
	ObjectMapBTreeValueSize = 16
)

// ObjectMapBTree represents the APFS object map B-tree
// This B-tree maps object identifiers and transaction identifiers to physical block numbers
type ObjectMapBTree struct {
	// The IO handle
	IOHandle *IOHandle

	// The encryption context
	EncryptionContext *EncryptionContext

	// The block number of B-tree root node
	RootNodeOID uint64

	// Note: Optional caching layers can be added for performance:
	// - DataBlockCache: LRU cache for data blocks (currently uncached)
	// - NodeCache: LRU cache for B-tree nodes (currently uncached)
	// These are performance optimizations, not required for correctness.
}

// ObjectMapKey represents a key in the object map B-tree
type ObjectMapKey struct {
	OID uint64
	XID uint64
}

// ObjectMapValue represents a value in the object map B-tree
type ObjectMapValue struct {
	ObjectFlags           uint32
	ObjectSize            uint32
	ObjectPhysicalAddress uint64
}

// ObjectMapDescriptor contains both key and value data from an object map entry
type ObjectMapDescriptor struct {
	Key   *ObjectMapKey
	Value *ObjectMapValue
}

// NewObjectMapDescriptor creates a new object map descriptor
func NewObjectMapDescriptor() (*ObjectMapDescriptor, error) {
	return &ObjectMapDescriptor{}, nil
}

// ReadKeyData reads the object map descriptor B-tree key data
func (d *ObjectMapDescriptor) ReadKeyData(data []byte) error {
	if d == nil {
		return fmt.Errorf("invalid object map descriptor")
	}

	if len(data) < ObjectMapBTreeKeySize {
		return fmt.Errorf("invalid data size value out of bounds: %d", len(data))
	}

	if isVerbose() {
		notifyPrintf("%s: object map B-tree key data:\n", "ReadKeyData")
		PrintData(data[:ObjectMapBTreeKeySize], true)
	}

	// Parse the key
	key, err := ParseObjectMapKey(data)
	if err != nil {
		return fmt.Errorf("unable to parse key data: %w", err)
	}

	d.Key = key

	if isVerbose() {
		notifyPrintf("%s: object identifier\t\t: %d\n", "ReadKeyData", d.Key.OID)
		notifyPrintf("%s: object transaction identifier\t: %d\n", "ReadKeyData", d.Key.XID)
		notifyPrintf("\n")
	}

	return nil
}

// ReadValueData reads the object map descriptor B-tree value data
func (d *ObjectMapDescriptor) ReadValueData(data []byte) error {
	if d == nil {
		return fmt.Errorf("invalid object map descriptor")
	}

	if len(data) < ObjectMapBTreeValueSize {
		return fmt.Errorf("invalid data size value out of bounds: %d", len(data))
	}

	if isVerbose() {
		notifyPrintf("%s: object map B-tree value data:\n", "ReadValueData")
		PrintData(data[:ObjectMapBTreeValueSize], true)
	}

	// Parse the value
	value, err := ParseObjectMapValue(data)
	if err != nil {
		return fmt.Errorf("unable to parse value data: %w", err)
	}

	d.Value = value

	if isVerbose() {
		notifyPrintf("%s: object flags\t\t\t: 0x%04x\n", "ReadValueData", d.Value.ObjectFlags)
		notifyPrintf("%s: object size\t\t\t: %d\n", "ReadValueData", d.Value.ObjectSize)
		notifyPrintf("%s: object physical address\t: %d\n", "ReadValueData", d.Value.ObjectPhysicalAddress)
		notifyPrintf("\n")
	}

	return nil
}

// Identifier returns the object identifier
func (d *ObjectMapDescriptor) Identifier() (uint64, error) {
	if d == nil {
		return 0, fmt.Errorf("invalid object map descriptor")
	}
	if d.Key == nil {
		return 0, fmt.Errorf("invalid key")
	}
	return d.Key.OID, nil
}

// TransactionIdentifier returns the transaction identifier
func (d *ObjectMapDescriptor) TransactionIdentifier() (uint64, error) {
	if d == nil {
		return 0, fmt.Errorf("invalid object map descriptor")
	}
	if d.Key == nil {
		return 0, fmt.Errorf("invalid key")
	}
	return d.Key.XID, nil
}

// PhysicalAddress returns the physical address
func (d *ObjectMapDescriptor) PhysicalAddress() (uint64, error) {
	if d == nil {
		return 0, fmt.Errorf("invalid object map descriptor")
	}
	if d.Value == nil {
		return 0, fmt.Errorf("invalid value")
	}
	return d.Value.ObjectPhysicalAddress, nil
}

// Flags returns the object flags
func (d *ObjectMapDescriptor) Flags() (uint32, error) {
	if d == nil {
		return 0, fmt.Errorf("invalid object map descriptor")
	}
	if d.Value == nil {
		return 0, fmt.Errorf("invalid value")
	}
	return d.Value.ObjectFlags, nil
}

// Size returns the object size
func (d *ObjectMapDescriptor) Size() (uint32, error) {
	if d == nil {
		return 0, fmt.Errorf("invalid object map descriptor")
	}
	if d.Value == nil {
		return 0, fmt.Errorf("invalid value")
	}
	return d.Value.ObjectSize, nil
}

// NewObjectMapBTree creates a new object map B-tree
func NewObjectMapBTree(
	ioHandle *IOHandle,
	encryptionContext *EncryptionContext,
	rootNodeOID uint64,
) (*ObjectMapBTree, error) {
	if ioHandle == nil {
		return nil, fmt.Errorf("invalid IO handle")
	}

	return &ObjectMapBTree{
		IOHandle:          ioHandle,
		EncryptionContext: encryptionContext,
		RootNodeOID:       rootNodeOID,
	}, nil
}

// RootNode retrieves the root node of the B-tree
func (bt *ObjectMapBTree) RootNode(
	reader io.ReaderAt,
	rootNodeOID uint64,
) (*BTreeNode, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid object map B-tree")
	}

	// Read the root node
	node, err := ReadBTreeNode(reader, bt.IOHandle, bt.EncryptionContext, rootNodeOID)
	if err != nil {
		return nil, fmt.Errorf("unable to read B-tree node: %w", err)
	}

	// Validate object type (must be OBJECT_TYPE_BTREE for root)
	if node.ObjectType != ObjectMapBTreeRootNodeType {
		return nil, fmt.Errorf("invalid object type: 0x%08x", node.ObjectType)
	}

	// Validate object subtype (must be OBJECT_SUBTYPE_OMAP)
	if node.ObjectSubtype != ObjectMapBTreeSubtype {
		return nil, fmt.Errorf("invalid object subtype: 0x%08x", node.ObjectSubtype)
	}

	// Validate flags (must be root and have fixed KV size)
	if !node.IsRootNode() || !node.HasFixedKVSize() {
		return nil, fmt.Errorf("unsupported flags: 0x%04x", node.NodeHeader.Flags)
	}

	// Validate node size
	if node.Info.NodeSize != 4096 {
		return nil, fmt.Errorf("invalid node size value out of bounds: %d", node.Info.NodeSize)
	}

	// Validate key size
	if node.Info.KeySize != ObjectMapBTreeKeySize {
		return nil, fmt.Errorf("invalid key size value out of bounds: %d", node.Info.KeySize)
	}

	// Validate value size
	if node.Info.ValueSize != ObjectMapBTreeValueSize {
		return nil, fmt.Errorf("invalid value size value out of bounds: %d", node.Info.ValueSize)
	}

	return node, nil
}

// SubNode retrieves a sub-node (child node) by block number
func (bt *ObjectMapBTree) SubNode(
	reader io.ReaderAt,
	subNodeOID uint64,
) (*BTreeNode, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid object map B-tree")
	}

	// Read the sub-node
	node, err := ReadBTreeNode(reader, bt.IOHandle, bt.EncryptionContext, subNodeOID)
	if err != nil {
		return nil, fmt.Errorf("unable to read B-tree node: %w", err)
	}

	// Validate object type (must be OBJECT_TYPE_BTREE_NODE for sub-nodes)
	if node.ObjectType != ObjectMapBTreeSubNodeType {
		return nil, fmt.Errorf("invalid object type: 0x%08x", node.ObjectType)
	}

	// Validate object subtype (must be OBJECT_SUBTYPE_OMAP)
	if node.ObjectSubtype != ObjectMapBTreeSubtype {
		return nil, fmt.Errorf("invalid object subtype: 0x%08x", node.ObjectSubtype)
	}

	// Validate flags (must NOT be root but must have fixed KV size)
	if node.IsRootNode() || !node.HasFixedKVSize() {
		return nil, fmt.Errorf("unsupported flags: 0x%04x", node.NodeHeader.Flags)
	}

	return node, nil
}

// GetEntryFromNodeByIdentifier finds an entry in a specific node by identifier
func (bt *ObjectMapBTree) EntryFromNodeByIdentifier(
	node *BTreeNode,
	oid uint64,
	xid uint64,
) (*BTreeEntry, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid object map B-tree")
	}

	if node == nil {
		return nil, fmt.Errorf("invalid B-tree node")
	}

	if isVerbose() {
		notifyPrintf("%s: retrieving B-tree entry identifier: %d (transaction: %d).\n",
			"GetEntryFromNodeByIdentifier", oid, xid)
	}

	isLeafNode := node.IsLeafNode()

	var previousEntry *BTreeEntry
	var previousObjectMapIdentifier uint64

	// Iterate through entries to find matching object identifier
	for entryIndex, entry := range node.Entries {
		// Validate key data
		if len(entry.KeyData) < ObjectMapBTreeKeySize {
			return nil, fmt.Errorf("invalid B-tree entry: %d - key data size value out of bounds: %d",
				entryIndex, len(entry.KeyData))
		}

		// Parse the key
		objectMapIdentifier := binary.LittleEndian.Uint64(entry.KeyData[0:8])
		objectMapTransaction := binary.LittleEndian.Uint64(entry.KeyData[8:16])

		if isVerbose() {
			notifyPrintf("%s: B-tree entry: %d, identifier: %d (transaction: %d)\n",
				"GetEntryFromNodeByIdentifier", entryIndex, objectMapIdentifier, objectMapTransaction)
		}

		// If we've passed the target identifier, stop searching
		if objectMapIdentifier > oid {
			break
		} else if objectMapIdentifier == oid && objectMapTransaction > xid {
			break
		}

		previousEntry = entry
		previousObjectMapIdentifier = objectMapIdentifier
	}

	// For leaf nodes, return entry only if we found exact match on object identifier
	if isLeafNode {
		if previousObjectMapIdentifier == oid {
			return previousEntry, nil
		}
		return nil, fmt.Errorf("entry not found for object identifier %d", oid)
	}

	// For branch nodes, return the entry to follow down the tree
	if previousEntry == nil {
		return nil, fmt.Errorf("entry not found for object identifier %d", oid)
	}

	return previousEntry, nil
}

// EntryByIdentifier retrieves a B-tree entry by object and transaction identifier
func (bt *ObjectMapBTree) EntryByIdentifier(
	reader io.ReaderAt,
	oid uint64,
	xid uint64,
) (*BTreeNode, *BTreeEntry, error) {
	if bt == nil {
		return nil, nil, fmt.Errorf("invalid object map B-tree")
	}

	// Read root node
	node, err := bt.RootNode(reader, bt.RootNodeOID)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to retrieve B-tree root node: %w", err)
	}

	// Navigate through the B-tree with recursion depth limit
	recursionDepth := 0

	for {
		if recursionDepth < 0 || recursionDepth > MaxObjectMapBTreeDepth {
			return nil, nil, fmt.Errorf("invalid recursion depth value out of bounds: %d", recursionDepth)
		}

		// Check if this is a leaf node
		isLeafNode := node.IsLeafNode()

		// Search for entry in this node
		entry, err := bt.EntryFromNodeByIdentifier(node, oid, xid)
		if err != nil {
			// Entry not found
			return nil, nil, nil
		}

		// If this is a leaf node, we found it
		if isLeafNode {
			return node, entry, nil
		}

		// This is a branch node - extract sub-node block number
		if len(entry.ValueData) != 8 {
			return nil, nil, fmt.Errorf("invalid B-tree entry - unsupported value data size: %d", len(entry.ValueData))
		}

		subNodeOID := binary.LittleEndian.Uint64(entry.ValueData[0:8])

		if isVerbose() {
			notifyPrintf("%s: B-tree sub node block number: %d\n",
				"GetEntryByIdentifier", subNodeOID)
		}

		// Read the sub-node
		node, err = bt.SubNode(reader, subNodeOID)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to retrieve B-tree sub node from block: %d: %w", subNodeOID, err)
		}

		recursionDepth++
	}
}

// DescriptorByObjectIdentifier retrieves the object map descriptor of a specific object identifier
func (bt *ObjectMapBTree) DescriptorByObjectIdentifier(
	reader io.ReaderAt,
	oid uint64,
	xid uint64,
) (*ObjectMapDescriptor, error) {
	if bt == nil {
		return nil, fmt.Errorf("invalid object map B-tree")
	}

	// Find the entry
	_, entry, err := bt.EntryByIdentifier(reader, oid, xid)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve entry from B-tree: %w", err)
	}

	if entry == nil {
		// Entry not found (not an error, just return nil)
		return nil, nil
	}

	// Create a new descriptor
	descriptor, err := NewObjectMapDescriptor()
	if err != nil {
		return nil, fmt.Errorf("unable to create object map descriptor: %w", err)
	}

	// Read key data
	if err := descriptor.ReadKeyData(entry.KeyData); err != nil {
		return nil, fmt.Errorf("unable to read object map descriptor key data: %w", err)
	}

	// Read value data
	if err := descriptor.ReadValueData(entry.ValueData); err != nil {
		return nil, fmt.Errorf("unable to read object map descriptor value data: %w", err)
	}

	return descriptor, nil
}

// PhysicalAddressForOID retrieves the physical block number for an object
// This is a convenience function that looks up an object in the object map
func (bt *ObjectMapBTree) PhysicalAddressForOID(
	reader io.ReaderAt,
	oid uint64,
	xid uint64,
) (uint64, error) {
	descriptor, err := bt.DescriptorByObjectIdentifier(reader, oid, xid)
	if err != nil {
		return 0, fmt.Errorf("unable to retrieve descriptor for object %d: %w", oid, err)
	}

	if descriptor == nil {
		return 0, fmt.Errorf("object %d not found in object map", oid)
	}

	return descriptor.Value.ObjectPhysicalAddress, nil
}

// ParseObjectMapKey parses an object map key from binary data
func ParseObjectMapKey(data []byte) (*ObjectMapKey, error) {
	if len(data) < ObjectMapBTreeKeySize {
		return nil, fmt.Errorf("invalid key size: expected at least %d bytes, got %d", ObjectMapBTreeKeySize, len(data))
	}

	return &ObjectMapKey{
		OID: binary.LittleEndian.Uint64(data[0:8]),
		XID: binary.LittleEndian.Uint64(data[8:16]),
	}, nil
}

// ParseObjectMapValue parses an object map value from binary data
func ParseObjectMapValue(data []byte) (*ObjectMapValue, error) {
	if len(data) < ObjectMapBTreeValueSize {
		return nil, fmt.Errorf("invalid value size: expected at least %d bytes, got %d", ObjectMapBTreeValueSize, len(data))
	}

	return &ObjectMapValue{
		ObjectFlags:           binary.LittleEndian.Uint32(data[0:4]),
		ObjectSize:            binary.LittleEndian.Uint32(data[4:8]),
		ObjectPhysicalAddress: binary.LittleEndian.Uint64(data[8:16]),
	}, nil
}
