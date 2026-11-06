package apfs

import (
	"encoding/binary"
	"fmt"
)

// ObjectSubtypeFextTree is the B-tree node object subtype used by the file
// extent tree (apfs_fext_tree_oid). Sealed volumes keep the file extents for
// their (hashed) file-system tree here instead of in the file-system tree.
const ObjectSubtypeFextTree uint32 = 0x0000001f

// BTreeNode represents a B-tree node
type BTreeNode struct {
	// The object type
	ObjectType uint32

	// The object subtype
	ObjectSubtype uint32

	// The B-tree node header
	NodeHeader *BTreeNodeHeader

	// The B-tree info (only present for root nodes)
	Info *BTreeInfo

	// The B-tree entries
	Entries []*BTreeEntry
}

// NewBTreeNode creates a new B-tree node
func NewBTreeNode() *BTreeNode {
	return &BTreeNode{
		Entries: make([]*BTreeEntry, 0),
	}
}

// ReadObjectData reads the APFS object header from binary data
func (n *BTreeNode) ReadObjectData(data []byte) error {
	if n == nil {
		return fmt.Errorf("invalid B-tree node")
	}

	if len(data) < ObjectHeaderSize {
		return fmt.Errorf("invalid data size: expected at least %d bytes for object header, got %d", ObjectHeaderSize, len(data))
	}

	// Read object type and subtype
	n.ObjectType = binary.LittleEndian.Uint32(data[24:28])
	n.ObjectSubtype = binary.LittleEndian.Uint32(data[28:32])

	// Validate object type (should be 0x00000000, 0x00000002, or 0x00000003 for B-tree nodes)
	objectType := n.ObjectType & 0x0fffffff
	if objectType != 0x00000000 && objectType != 0x00000002 && objectType != 0x00000003 {
		return fmt.Errorf("invalid object type: 0x%08x", n.ObjectType)
	}

	return nil
}

// ReadData reads the B-tree node from binary data
func (n *BTreeNode) ReadData(data []byte) error {
	if n == nil {
		return fmt.Errorf("invalid B-tree node")
	}

	if n.NodeHeader != nil {
		return fmt.Errorf("node header already set")
	}

	minimumDataSize := ObjectHeaderSize + BTreeNodeHeaderSize + BTreeInfoSize
	if len(data) < minimumDataSize {
		return fmt.Errorf("invalid data size: expected at least %d bytes, got %d", minimumDataSize, len(data))
	}

	// Read object header
	if err := n.ReadObjectData(data); err != nil {
		return fmt.Errorf("unable to read object data: %w", err)
	}

	dataOffset := ObjectHeaderSize

	// Read node header
	n.NodeHeader = NewBTreeNodeHeader()
	if err := n.NodeHeader.ReadData(data[dataOffset : dataOffset+BTreeNodeHeaderSize]); err != nil {
		return fmt.Errorf("unable to read node header: %w", err)
	}
	dataOffset += BTreeNodeHeaderSize

	// Calculate remaining data size
	remainingDataSize := len(data) - minimumDataSize

	// Validate offsets and sizes
	if int(n.NodeHeader.EntriesDataOffset) >= remainingDataSize {
		return fmt.Errorf("invalid entries data offset: %d >= %d", n.NodeHeader.EntriesDataOffset, remainingDataSize)
	}
	remainingDataSize -= int(n.NodeHeader.EntriesDataOffset)

	if int(n.NodeHeader.EntriesDataSize) > remainingDataSize {
		return fmt.Errorf("invalid entries data size: %d > %d", n.NodeHeader.EntriesDataSize, remainingDataSize)
	}

	// Determine B-tree info offset
	infoOffset := len(data)

	// Read B-tree info if this is a root node (flag 0x0001)
	if (n.NodeHeader.Flags & 0x0001) != 0 {
		n.Info = NewBTreeInfo()
		infoDataOffset := len(data) - BTreeInfoSize
		if err := n.Info.ReadData(data[infoDataOffset:]); err != nil {
			return fmt.Errorf("unable to read B-tree info: %w", err)
		}
		infoOffset -= BTreeInfoSize
	}

	// Parse entries
	if err := n.parseEntries(data, dataOffset, infoOffset); err != nil {
		return fmt.Errorf("unable to parse entries: %w", err)
	}

	return nil
}

// parseEntries parses B-tree entries from the node data
func (n *BTreeNode) parseEntries(data []byte, dataOffset int, infoOffset int) error {
	// Determine entry size based on fixed/variable flag
	var entryDataSize int
	hasFixedSizeKeys := (n.NodeHeader.Flags & 0x0004) != 0

	if hasFixedSizeKeys {
		entryDataSize = 4 // sizeof(BTreeFixedSizeEntry)
	} else {
		entryDataSize = 8 // sizeof(BTreeVariableSizeEntry)
	}

	// Validate number of keys
	if int(n.NodeHeader.NumberOfKeys) > int(n.NodeHeader.EntriesDataSize)/entryDataSize {
		return fmt.Errorf("invalid number of keys: %d", n.NodeHeader.NumberOfKeys)
	}

	// Current position in the entry table (TOC starts at btn_data + EntriesDataOffset)
	currentOffset := dataOffset + int(n.NodeHeader.EntriesDataOffset)

	// Parse each entry
	for i := uint32(0); i < n.NodeHeader.NumberOfKeys; i++ {
		var keyDataOffset, keyDataSize, valueDataOffset, valueDataSize uint16

		if !hasFixedSizeKeys {
			// Variable size entry
			if currentOffset+8 > len(data) {
				return fmt.Errorf("invalid entry offset: %d", currentOffset)
			}

			keyDataOffset = binary.LittleEndian.Uint16(data[currentOffset : currentOffset+2])
			keyDataSize = binary.LittleEndian.Uint16(data[currentOffset+2 : currentOffset+4])
			valueDataOffset = binary.LittleEndian.Uint16(data[currentOffset+4 : currentOffset+6])
			valueDataSize = binary.LittleEndian.Uint16(data[currentOffset+6 : currentOffset+8])
		} else {
			// Fixed size entry
			if currentOffset+4 > len(data) {
				return fmt.Errorf("invalid entry offset: %d", currentOffset)
			}

			keyDataOffset = binary.LittleEndian.Uint16(data[currentOffset : currentOffset+2])
			valueDataOffset = binary.LittleEndian.Uint16(data[currentOffset+2 : currentOffset+4])

			// For fixed size entries, size depends on object subtype
			switch n.ObjectSubtype {
			case 0x0000000b: // Object map B-tree
				keyDataSize = 16   // sizeof(fsapfs_object_map_btree_key_t)
				valueDataSize = 16 // sizeof(fsapfs_object_map_btree_value_t)
			case ObjectSubtypeFextTree: // File extent tree
				keyDataSize = 16   // sizeof(j_file_extent_key_t)
				valueDataSize = 16 // sizeof(j_file_extent_val_t) without the trailing crypto id
			default:
				return fmt.Errorf("unsupported object subtype for fixed size entries: 0x%08x", n.ObjectSubtype)
			}

			// For non-leaf nodes, value is just a block number (8 bytes)
			if (n.NodeHeader.Flags & 0x0002) == 0 {
				valueDataSize = 8
			}
		}

		currentOffset += entryDataSize

		// Calculate absolute offsets for key and value data
		// Per drat implementation (include/drat/func/btree.c lines 60-62, 83, 123):
		// - toc_start = btn_data + table_space.off
		// - key_start = toc_start + table_space.len  (keys start AFTER the TOC)
		// - keyDataOffset is relative to key_start
		// - valueDataOffset is relative to val_end (grows backward from infoOffset)
		keyStart := uint16(dataOffset) + n.NodeHeader.EntriesDataOffset + n.NodeHeader.EntriesDataSize
		absoluteKeyOffset := keyStart + keyDataOffset
		absoluteValueOffset := uint16(infoOffset) - valueDataOffset

		// Validate offsets
		if int(absoluteKeyOffset) > len(data) || int(keyDataSize) > len(data)-int(absoluteKeyOffset) {
			return fmt.Errorf("invalid key data offset: offset=%d, size=%d, dataLen=%d", absoluteKeyOffset, keyDataSize, len(data))
		}

		if int(absoluteValueOffset) > len(data) || int(valueDataSize) > len(data)-int(absoluteValueOffset) {
			return fmt.Errorf("invalid value data offset: offset=%d, size=%d, dataLen=%d", absoluteValueOffset, valueDataSize, len(data))
		}

		// Extract key and value data
		keyData := data[absoluteKeyOffset : absoluteKeyOffset+keyDataSize]
		valueData := data[absoluteValueOffset : absoluteValueOffset+valueDataSize]

		// Create entry
		entry := NewBTreeEntry()
		if err := entry.SetKeyData(keyData); err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
		if err := entry.SetValueData(valueData); err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}

		n.Entries = append(n.Entries, entry)
	}

	return nil
}

// IsLeafNode returns true if this is a leaf node
func (n *BTreeNode) IsLeafNode() bool {
	if n == nil || n.NodeHeader == nil {
		return false
	}
	return n.NodeHeader.IsLeaf()
}

// IsRootNode returns true if this is a root node
func (n *BTreeNode) IsRootNode() bool {
	if n == nil || n.NodeHeader == nil {
		return false
	}
	return n.NodeHeader.IsRoot()
}

// HasFixedKVSize returns true if this node has fixed key-value size
func (n *BTreeNode) HasFixedKVSize() bool {
	if n == nil || n.NodeHeader == nil {
		return false
	}
	return n.NodeHeader.HasFixedKVSize()
}

// NumberOfEntries returns the number of entries in this node
func (n *BTreeNode) NumberOfEntries() int {
	if n == nil {
		return 0
	}
	return len(n.Entries)
}

// EntryByIndex returns the entry at the specified index
func (n *BTreeNode) EntryByIndex(index int) (*BTreeEntry, error) {
	if n == nil {
		return nil, fmt.Errorf("invalid B-tree node")
	}

	if index < 0 || index >= len(n.Entries) {
		return nil, fmt.Errorf("index out of bounds: %d (total entries: %d)", index, len(n.Entries))
	}

	return n.Entries[index], nil
}
