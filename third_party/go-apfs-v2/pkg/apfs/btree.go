// The APFS B-tree definition
package apfs

// BTreeNodeHeader represents the APFS B-tree node header structure
type BTreeNodeHeader struct {
	// The node flags
	// Consists of 2 bytes
	Flags uint16

	// The level
	// Consists of 2 bytes
	Level uint16

	// The number of keys
	// Consists of 4 bytes
	NumberOfKeys uint32

	// The entries data offset
	// Consists of 2 bytes
	EntriesDataOffset uint16

	// The entries data size
	// Consists of 2 bytes
	EntriesDataSize uint16

	// The unused data offset
	// Consists of 2 bytes
	UnusedDataOffset uint16

	// The unused data size
	// Consists of 2 bytes
	UnusedDataSize uint16

	// The key free list offset
	// Consists of 2 bytes
	KeyFreeListOffset uint16

	// The key free list size
	// Consists of 2 bytes
	KeyFreeListSize uint16

	// The value free list offset
	// Consists of 2 bytes
	ValueFreeListOffset uint16

	// The value free list size
	// Consists of 2 bytes
	ValueFreeListSize uint16
}

// BTreeFixedSizeEntry represents the APFS B-tree fixed size entry structure
type BTreeFixedSizeEntry struct {
	// The key data offset
	// Consists of 2 bytes
	KeyDataOffset uint16

	// The value data offset
	// Consists of 2 bytes
	ValueDataOffset uint16
}

// BTreeVariableSizeEntry represents the APFS B-tree variable size entry structure
type BTreeVariableSizeEntry struct {
	// The key data offset
	// Consists of 2 bytes
	KeyDataOffset uint16

	// The key data size
	// Consists of 2 bytes
	KeyDataSize uint16

	// The value data offset
	// Consists of 2 bytes
	ValueDataOffset uint16

	// The value data size
	// Consists of 2 bytes
	ValueDataSize uint16
}

// BTreeInfo represents the APFS B-tree info structure
type BTreeInfo struct {
	// The flags
	// Consists of 4 bytes
	Flags uint32

	// The node size
	// Consists of 4 bytes
	NodeSize uint32

	// The key size
	// Consists of 4 bytes
	KeySize uint32

	// The value size
	// Consists of 4 bytes
	ValueSize uint32

	// The maximum key size
	// Consists of 4 bytes
	MaximumKeySize uint32

	// The maximum value size
	// Consists of 4 bytes
	MaximumValueSize uint32

	// The total number of keys
	// Consists of 8 bytes
	TotalNumberOfKeys uint64

	// The total number of nodes
	// Consists of 8 bytes
	TotalNumberOfNodes uint64
}
