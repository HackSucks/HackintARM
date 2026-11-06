package cli

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

// runInspectBlock reads one block by physical address and displays its
// object header, checksum validation and type-specific decode.
func runInspectBlock(imagePath string, readBlockAddr uint64, readVerbose bool) error {
	// Open the container image with content-based format detection
	reader, containerOffset, closer, err := disk.OpenWithOffset(imagePath)
	if err != nil {
		return withCode(ExitBadImage, fmt.Errorf("unable to open container: %w", err))
	}
	defer closer.Close()

	// Block addresses are container-relative; rebase the reader when the
	// container starts at a non-zero offset (e.g. GPT-partitioned raw image)
	file := reader
	if containerOffset != 0 {
		file = io.NewSectionReader(reader, containerOffset, math.MaxInt64-containerOffset)
	}

	// Read block 0 to get block size
	block0 := make([]byte, 4096) // Start with default block size
	if _, err := file.ReadAt(block0, 0); err != nil {
		return fmt.Errorf("unable to read block 0: %w", err)
	}

	// Parse block size from container superblock
	// Block size is at offset 36 (4 bytes)
	blockSize := binary.LittleEndian.Uint32(block0[36:40])

	if readVerbose {
		fmt.Printf("Container block size: %d bytes\n", blockSize)
		fmt.Printf("Reading block at address: 0x%x (%d)\n\n", readBlockAddr, readBlockAddr)
	}

	// Calculate offset and read the requested block
	offset := int64(readBlockAddr) * int64(blockSize)
	blockData := make([]byte, blockSize)

	if _, err := file.ReadAt(blockData, offset); err != nil {
		if err == io.EOF {
			return fmt.Errorf("block address 0x%x is beyond container size", readBlockAddr)
		}
		return fmt.Errorf("unable to read block at 0x%x: %w", readBlockAddr, err)
	}

	// Display block information
	if err := displayBlockInfo(blockData, readBlockAddr, readVerbose); err != nil {
		return err
	}

	return nil
}

// displayBlockInfo analyzes and displays information about a block
func displayBlockInfo(blockData []byte, blockAddr uint64, verbose bool) error {
	if len(blockData) < 32 {
		return fmt.Errorf("block data too small (< 32 bytes)")
	}

	// Parse object header
	checksum := binary.LittleEndian.Uint64(blockData[0:8])
	objectID := binary.LittleEndian.Uint64(blockData[8:16])
	transactionID := binary.LittleEndian.Uint64(blockData[16:24])
	objectType := binary.LittleEndian.Uint32(blockData[24:28])
	objectSubtype := binary.LittleEndian.Uint32(blockData[28:32])

	// Display header information
	fmt.Println("╭─────────────────────────────────────────────────────╮")
	fmt.Printf("│ Block: 0x%-42x │\n", blockAddr)
	fmt.Println("╰─────────────────────────────────────────────────────╯")
	fmt.Println()

	fmt.Println("  Object Header")
	fmt.Printf("    %-26s  0x%016x\n", "Checksum", checksum)
	fmt.Printf("    %-26s  0x%016x (%d)\n", "Object identifier", objectID, objectID)
	fmt.Printf("    %-26s  0x%016x (%d)\n", "Transaction identifier", transactionID, transactionID)
	fmt.Printf("    %-26s  0x%08x (%s)\n", "Object type", objectType, getObjectTypeName(objectType))
	fmt.Printf("    %-26s  0x%08x (%s)\n", "Object subtype", objectSubtype, getObjectSubtypeName(objectSubtype))
	fmt.Println()

	// Validate checksum (Fletcher 64)
	// Save original checksum and zero it out for calculation
	blockDataCopy := make([]byte, len(blockData))
	copy(blockDataCopy, blockData)
	binary.LittleEndian.PutUint64(blockDataCopy[0:8], 0)

	calculatedChecksum, err := apfs.CalculateFletcher64(blockDataCopy, 0)
	if err != nil {
		fmt.Printf("  ! Unable to calculate checksum: %v\n", err)
	} else if calculatedChecksum == checksum {
		fmt.Println("  ✓ Checksum valid")
	} else {
		fmt.Printf("  ✗ Checksum invalid (expected: 0x%016x, calculated: 0x%016x)\n", checksum, calculatedChecksum)
	}
	fmt.Println()

	// Display type-specific information
	if err := displayTypeSpecificInfo(blockData, objectType, objectSubtype, verbose); err != nil {
		fmt.Printf("  Warning: Unable to parse type-specific data: %v\n\n", err)
	}

	// Display raw data if verbose
	if verbose {
		fmt.Println("  Raw Block Data")
		fmt.Println("  " + hex.Dump(blockData))
	}

	return nil
}

// displayTypeSpecificInfo displays information specific to the object type.
// Type values are Apple's OBJECT_TYPE_* constants; see objectTypeNames.
func displayTypeSpecificInfo(blockData []byte, objectType, objectSubtype uint32, verbose bool) error {
	baseType := objectType & 0x0000FFFF

	switch baseType {
	case 0x0001: // NX_SUPERBLOCK
		return displayContainerSuperblock(blockData, verbose)
	case 0x0002, 0x0003: // BTREE, BTREE_NODE
		return displayBTreeNode(blockData, verbose)
	case 0x0005: // SPACEMAN
		return displaySpaceManager(blockData, verbose)
	case 0x000b: // OMAP
		return displayObjectMap(blockData, verbose)
	case 0x000d: // FS (volume superblock)
		return displayVolumeSuperblock(blockData, verbose)
	case 0x000e: // FSTREE (file-system tree)
		return displayFSTree(blockData, verbose)
	case 0x000f: // BLOCKREFTREE (extentref tree)
		return displayBTreeNode(blockData, verbose)
	case 0x0010: // SNAPMETATREE
		return displayBTreeNode(blockData, verbose)
	case 0x001f: // FEXT_TREE
		return displayBTreeNode(blockData, verbose)
	default:
		if verbose {
			fmt.Printf("  Type-specific parsing not implemented for type 0x%08x\n", objectType)
		}
		return nil
	}
}

// displayContainerSuperblock displays container superblock information
func displayContainerSuperblock(blockData []byte, verbose bool) error {
	if len(blockData) < 200 {
		return fmt.Errorf("insufficient data for container superblock")
	}

	magic := binary.LittleEndian.Uint32(blockData[32:36])
	blockSize := binary.LittleEndian.Uint32(blockData[36:40])
	blockCount := binary.LittleEndian.Uint64(blockData[40:48])

	fmt.Println("  Container Superblock")
	fmt.Printf("    %-20s  0x%08x (%c%c%c%c)\n", "Magic", magic,
		blockData[32], blockData[33], blockData[34], blockData[35])
	fmt.Printf("    %-20s  %d bytes\n", "Block size", blockSize)
	fmt.Printf("    %-20s  %d (%s)\n", "Block count", blockCount, formatNumber(blockCount))

	if verbose {
		features := binary.LittleEndian.Uint64(blockData[48:56])
		readOnlyFeatures := binary.LittleEndian.Uint64(blockData[56:64])
		incompatFeatures := binary.LittleEndian.Uint64(blockData[64:72])

		fmt.Printf("    %-20s  0x%016x\n", "Features", features)
		fmt.Printf("    %-26s  0x%016x\n", "Read-only compat. features", readOnlyFeatures)
		fmt.Printf("    %-26s  0x%016x\n", "Incompatible features", incompatFeatures)
	}

	fmt.Println()
	return nil
}

// displayBTreeNode displays B-tree node information
func displayBTreeNode(blockData []byte, verbose bool) error {
	if len(blockData) < 56 {
		return fmt.Errorf("insufficient data for B-tree node")
	}

	// Parse B-tree node header (starts at offset 32, after obj_phys_t)
	flags := binary.LittleEndian.Uint16(blockData[32:34])
	level := binary.LittleEndian.Uint16(blockData[34:36])
	keyCount := binary.LittleEndian.Uint32(blockData[36:40])
	tableSpaceOff := binary.LittleEndian.Uint16(blockData[40:42])
	tableSpaceLen := binary.LittleEndian.Uint16(blockData[42:44])
	freeSpaceOff := binary.LittleEndian.Uint16(blockData[44:46])
	freeSpaceLen := binary.LittleEndian.Uint16(blockData[46:48])

	fmt.Println("  B-Tree Node")
	fmt.Printf("    %-25s  0x%04x", "Flags", flags)

	// Decode flags
	var flagStrs []string
	if flags&0x0001 != 0 {
		flagStrs = append(flagStrs, "ROOT")
	}
	if flags&0x0002 != 0 {
		flagStrs = append(flagStrs, "LEAF")
	}
	if flags&0x0004 != 0 {
		flagStrs = append(flagStrs, "FIXED_KV_SIZE")
	}
	if flags&0x0008 != 0 {
		flagStrs = append(flagStrs, "HASHED")
	}
	if flags&0x0010 != 0 {
		flagStrs = append(flagStrs, "NOHEADER")
	}
	if flags&0x8000 != 0 {
		flagStrs = append(flagStrs, "CHECK_KOFF_INVAL")
	}

	if len(flagStrs) > 0 {
		fmt.Printf(" (%s)", formatList(flagStrs))
	}
	fmt.Println()

	// Node type
	nodeType := "Index node"
	if flags&0x0001 != 0 && flags&0x0002 != 0 {
		nodeType = "Root+Leaf node"
	} else if flags&0x0001 != 0 {
		nodeType = "Root node"
	} else if flags&0x0002 != 0 {
		nodeType = "Leaf node"
	}
	fmt.Printf("    %-25s  %s\n", "Node type", nodeType)

	fmt.Printf("    %-25s  %d\n", "Level", level)
	fmt.Printf("    %-25s  %d\n", "Key count", keyCount)

	if verbose {
		fmt.Printf("    %-25s  offset: %d, length: %d\n", "Table space", tableSpaceOff, tableSpaceLen)
		fmt.Printf("    %-25s  offset: %d, length: %d\n", "Free space", freeSpaceOff, freeSpaceLen)
	}

	fmt.Println()

	// If verbose, parse and display the entries
	if verbose {
		if err := displayBTreeEntries(blockData); err != nil {
			fmt.Printf("    Warning: Unable to parse B-tree entries: %v\n", err)
		}
	}

	return nil
}

// displaySpaceManager displays space manager information
func displaySpaceManager(blockData []byte, verbose bool) error {
	fmt.Println("  Space Manager")
	fmt.Println("    (Detailed parsing not yet implemented)")
	fmt.Println()
	return nil
}

// displayObjectMap displays object map information
func displayObjectMap(blockData []byte, verbose bool) error {
	if len(blockData) < 64 {
		return fmt.Errorf("insufficient data for object map")
	}

	flags := binary.LittleEndian.Uint32(blockData[32:36])
	snapshotCount := binary.LittleEndian.Uint32(blockData[36:40])
	treeType := binary.LittleEndian.Uint32(blockData[40:44])
	snapshotTreeType := binary.LittleEndian.Uint32(blockData[44:48])
	treeOID := binary.LittleEndian.Uint64(blockData[48:56])
	snapshotTreeOID := binary.LittleEndian.Uint64(blockData[56:64])

	fmt.Println("  Object Map")
	fmt.Printf("    %-25s  0x%08x\n", "Flags", flags)
	fmt.Printf("    %-25s  %d\n", "Snapshot count", snapshotCount)
	fmt.Printf("    %-25s  0x%08x (%s)\n", "Tree type", treeType, getObjectTypeName(treeType))
	fmt.Printf("    %-25s  0x%08x (%s)\n", "Snapshot tree type", snapshotTreeType, getObjectTypeName(snapshotTreeType))
	fmt.Printf("    %-25s  0x%016x\n", "Tree object identifier", treeOID)
	if snapshotTreeOID != 0 {
		fmt.Printf("    %-25s  0x%016x\n", "Snapshot tree object identifier", snapshotTreeOID)
	}
	fmt.Println()
	return nil
}

// displayFSTree displays file system B-tree information
func displayFSTree(blockData []byte, verbose bool) error {
	fmt.Println("  File system B-Tree")

	// First display the B-tree node structure
	if err := displayBTreeNode(blockData, verbose); err != nil {
		return err
	}

	// If verbose, try to parse and display the entries
	if verbose {
		if err := displayBTreeEntries(blockData); err != nil {
			fmt.Printf("    Warning: Unable to parse B-tree entries: %v\n", err)
		}
	}

	return nil
}

// displayBTreeEntries attempts to parse and display B-tree key-value entries
func displayBTreeEntries(blockData []byte) error {
	if len(blockData) < 56 {
		return fmt.Errorf("insufficient data")
	}

	// Parse header
	subtype := binary.LittleEndian.Uint32(blockData[28:32])
	flags := binary.LittleEndian.Uint16(blockData[32:34])
	keyCount := binary.LittleEndian.Uint32(blockData[36:40])
	tableSpaceOff := binary.LittleEndian.Uint16(blockData[40:42])
	tableSpaceLen := binary.LittleEndian.Uint16(blockData[42:44])

	if keyCount == 0 {
		return nil
	}

	fmt.Println()
	fmt.Println("  B-Tree Entries:")
	fmt.Printf("    Entry count: %d\n", keyCount)
	fmt.Printf("    Table space: offset %d, length %d\n", tableSpaceOff, tableSpaceLen)

	// Check if this is a fixed or variable key/value size node
	hasFixedKV := (flags & 0x0004) != 0

	// The btree_node_phys_t header is 56 bytes, btn_data starts there
	// The TOC starts at btn_data + table_space.off
	btnDataStart := 56
	tocOffset := btnDataStart + int(tableSpaceOff)

	if hasFixedKV {
		fmt.Println("    Format: Fixed key-value size")
		// For fixed size OMAP: keys grow forward from after TOC, values grow backward from end
		// Keys start at: btn_data + table_space.off + table_space.len
		keysStart := btnDataStart + int(tableSpaceOff) + int(tableSpaceLen)

		// Values grow backward from the end of the block
		// For ROOT nodes, there's a 40-byte footer, otherwise values end at block end
		valuesEnd := len(blockData)
		if flags&0x0001 != 0 { // ROOT node
			valuesEnd -= 40 // sizeof(btree_info_t)
		}

		for i := uint32(0); i < keyCount && tocOffset+4 <= len(blockData); i++ {
			keyOff := binary.LittleEndian.Uint16(blockData[tocOffset : tocOffset+2])
			valOff := binary.LittleEndian.Uint16(blockData[tocOffset+2 : tocOffset+4])

			// Key offset is relative to keysStart
			keyAbsoluteOff := keysStart + int(keyOff)
			// Value offset grows backward from valuesEnd
			valAbsoluteOff := valuesEnd - int(valOff) - 16 // 16 bytes per OMAP value

			fmt.Printf("      Entry %d: key offset=%d (abs: %d), val offset=%d (abs: %d)\n",
				i, keyOff, keyAbsoluteOff, valOff, valAbsoluteOff)

			// Parse object map entry (subtype 0x0b)
			if subtype == 0x0b && keyAbsoluteOff+16 <= len(blockData) && valAbsoluteOff+16 <= len(blockData) {
				// Key: OID (8 bytes) + XID (8 bytes)
				oid := binary.LittleEndian.Uint64(blockData[keyAbsoluteOff : keyAbsoluteOff+8])
				xid := binary.LittleEndian.Uint64(blockData[keyAbsoluteOff+8 : keyAbsoluteOff+16])
				// Value: flags (4 bytes) + size (4 bytes) + paddr (8 bytes)
				oflags := binary.LittleEndian.Uint32(blockData[valAbsoluteOff : valAbsoluteOff+4])
				osize := binary.LittleEndian.Uint32(blockData[valAbsoluteOff+4 : valAbsoluteOff+8])
				paddr := binary.LittleEndian.Uint64(blockData[valAbsoluteOff+8 : valAbsoluteOff+16])
				fmt.Printf("        OMAP: OID 0x%x @ XID %d -> Physical block 0x%x (flags=0x%x, size=%d)\n",
					oid, xid, paddr, oflags, osize)
			}

			tocOffset += 4
		}
	} else {
		fmt.Println("    Format: Variable key-value size")
		// For variable size, TOC contains offset+length (kvloc_t)
		for i := uint32(0); i < keyCount && tocOffset+8 <= len(blockData); i++ {
			keyOff := binary.LittleEndian.Uint16(blockData[tocOffset : tocOffset+2])
			keyLen := binary.LittleEndian.Uint16(blockData[tocOffset+2 : tocOffset+4])
			valOff := binary.LittleEndian.Uint16(blockData[tocOffset+4 : tocOffset+6])
			valLen := binary.LittleEndian.Uint16(blockData[tocOffset+6 : tocOffset+8])

			fmt.Printf("      Entry %d:\n", i)
			fmt.Printf("        Key: offset=%d, length=%d\n", keyOff, keyLen)
			fmt.Printf("        Val: offset=%d, length=%d\n", valOff, valLen)

			// Per drat: key_start = toc_start + toc_len, keys are relative to key_start
			// Values are relative to val_end (grow backward from end)
			keyStart := btnDataStart + int(tableSpaceOff) + int(tableSpaceLen)
			keyAbsoluteOff := keyStart + int(keyOff)
			valAbsoluteOff := len(blockData) - int(valOff)
			if flags&0x0001 != 0 { // ROOT node has footer
				valAbsoluteOff -= 40 // sizeof(btree_info_t)
			}

			// Try to parse the key (j_key_t: first 8 bytes is obj_id_and_type)
			if keyAbsoluteOff+8 <= len(blockData) && keyLen >= 8 {
				objIDAndType := binary.LittleEndian.Uint64(blockData[keyAbsoluteOff : keyAbsoluteOff+8])
				objID := objIDAndType & 0x0FFFFFFFFFFFFFFF
				objType := (objIDAndType >> 60) & 0xF
				fmt.Printf("        Key: FSOID=%d, type=0x%x (%s)\n", objID, objType, apfs.FileSystemRecordTypeName(uint8(objType)))
			}

			// For leaf nodes, show value data
			if flags&0x0002 != 0 && valAbsoluteOff+int(valLen) <= len(blockData) && valLen > 0 {
				// Show first few bytes of value
				maxShow := int(valLen)
				if maxShow > 32 {
					maxShow = 32
				}
				fmt.Printf("        Val data (first %d bytes): %x\n", maxShow, blockData[valAbsoluteOff:valAbsoluteOff+maxShow])
			}

			tocOffset += 8
		}
	}

	return nil
}

// formatList formats a string slice as a comma-separated list
func formatList(items []string) string {
	if len(items) == 0 {
		return ""
	}
	result := items[0]
	for i := 1; i < len(items); i++ {
		result += ", " + items[i]
	}
	return result
}

// displayVolumeSuperblock displays volume superblock information
func displayVolumeSuperblock(blockData []byte, verbose bool) error {
	if len(blockData) < 200 {
		return fmt.Errorf("insufficient data for volume superblock")
	}

	magic := binary.LittleEndian.Uint32(blockData[32:36])
	fsIndex := binary.LittleEndian.Uint32(blockData[36:40])
	features := binary.LittleEndian.Uint64(blockData[40:48])

	fmt.Println("  Volume Superblock")
	fmt.Printf("    %-20s  0x%08x (%c%c%c%c)\n", "Magic", magic,
		blockData[32], blockData[33], blockData[34], blockData[35])
	fmt.Printf("    %-26s  %d\n", "Volume index", fsIndex)
	fmt.Printf("    %-20s  0x%016x\n", "Features", features)

	if verbose {
		roFeatures := binary.LittleEndian.Uint64(blockData[48:56])
		incompatFeatures := binary.LittleEndian.Uint64(blockData[56:64])

		fmt.Printf("    %-26s  0x%016x\n", "Read-only compat. features", roFeatures)
		fmt.Printf("    %-26s  0x%016x\n", "Incompatible features", incompatFeatures)
	}

	fmt.Println()
	return nil
}

// objectTypeNames maps the low half of o_type to Apple's OBJECT_TYPE_*
// constant name. Values are from the "Object Types" section of the Apple File
// System Reference.
var objectTypeNames = map[uint32]string{
	0x0000: "INVALID",
	0x0001: "NX_SUPERBLOCK",
	0x0002: "BTREE",
	0x0003: "BTREE_NODE",
	0x0005: "SPACEMAN",
	0x0006: "SPACEMAN_CAB",
	0x0007: "SPACEMAN_CIB",
	0x0008: "SPACEMAN_BITMAP",
	0x0009: "SPACEMAN_FREE_QUEUE",
	0x000a: "EXTENT_LIST_TREE",
	0x000b: "OMAP",
	0x000c: "CHECKPOINT_MAP",
	0x000d: "FS",
	0x000e: "FSTREE",
	0x000f: "BLOCKREFTREE",
	0x0010: "SNAPMETATREE",
	0x0011: "NX_REAPER",
	0x0012: "NX_REAP_LIST",
	0x0013: "OMAP_SNAPSHOT",
	0x0014: "EFI_JUMPSTART",
	0x0015: "FUSION_MIDDLE_TREE",
	0x0016: "NX_FUSION_WBC",
	0x0017: "NX_FUSION_WBC_LIST",
	0x0018: "ER_STATE",
	0x0019: "GBITMAP",
	0x001a: "GBITMAP_TREE",
	0x001b: "GBITMAP_BLOCK",
	0x001c: "ER_RECOVERY_BLOCK",
	0x001d: "SNAP_META_EXT",
	0x001e: "INTEGRITY_META",
	0x001f: "FEXT_TREE",
	0x0020: "RESERVED_20",
	0x00ff: "TEST",
}

// keybagObjectTypes are the three object types Apple gives as four-character
// codes rather than small integers, so they do not fit objectTypeNames.
var keybagObjectTypes = map[uint32]string{
	0x6b657973: "CONTAINER_KEYBAG", // 'keys'
	0x72656373: "VOLUME_KEYBAG",    // 'recs'
	0x6d6b6579: "MEDIA_KEYBAG",     // 'mkey'
}

// getObjectTypeName returns Apple's OBJECT_TYPE_* name for an object type.
func getObjectTypeName(objectType uint32) string {
	if name, ok := keybagObjectTypes[objectType]; ok {
		return name
	}
	typeValue := objectType & 0x0000FFFF
	if name, ok := objectTypeNames[typeValue]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN_%#x", typeValue)
}

// getObjectSubtypeName returns a human-readable name for an object subtype. In
// APFS o_subtype holds an object type, so it uses the same table.
func getObjectSubtypeName(objectSubtype uint32) string {
	if objectSubtype == 0 {
		return "NONE"
	}
	return getObjectTypeName(objectSubtype)
}
