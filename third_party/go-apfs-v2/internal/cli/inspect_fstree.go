package cli

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

// runInspectFSTree interactively explores the file-system B-tree of the
// selected volume. The tree root addresses are resolved automatically from
// the container; fsTreeRoot/omapRoot override them when non-zero.
func runInspectFSTree(imagePath string, fsTreeRoot, omapRoot uint64) error {
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

	// Resolve the volume file-system tree and object map tree root addresses unless the
	// caller supplied explicit overrides
	if fsTreeRoot == 0 || omapRoot == 0 {
		fsAddr, omapAddr, err := resolveVolumeTreeRoots(file)
		if err != nil {
			return fmt.Errorf("unable to auto-resolve tree roots (pass --fstree-root/--omap-root explicitly): %w", err)
		}
		if fsTreeRoot == 0 {
			fsTreeRoot = fsAddr
		}
		if omapRoot == 0 {
			omapRoot = omapAddr
		}
		fmt.Printf("Resolved tree roots: file-system tree %#x, object map %#x\n\n", fsTreeRoot, omapRoot)
	}

	// Determine block size from block 0
	block0 := make([]byte, 4096)
	if _, err := file.ReadAt(block0, 0); err != nil {
		return fmt.Errorf("unable to read block 0: %w", err)
	}
	blockSize := binary.LittleEndian.Uint32(block0[36:40])
	if blockSize == 0 {
		blockSize = 4096
	}

	// Read file system tree root node
	fmt.Printf("Reading the file-system tree root node (block %#x) ... ", fsTreeRoot)
	fsRootData, err := readBlock(file, fsTreeRoot, blockSize)
	if err != nil {
		return fmt.Errorf("failed to read fs tree root: %w", err)
	}
	fmt.Print("validating ... ")
	if apfs.ValidateChecksum(fsRootData) {
		fmt.Println("OK.")
	} else {
		fmt.Println("FAILED.")
	}
	fmt.Println()

	// Read object map tree root node
	fmt.Printf("Reading the object map root node (block %#x) ... ", omapRoot)
	omapRootData, err := readBlock(file, omapRoot, blockSize)
	if err != nil {
		return fmt.Errorf("failed to read object map tree root: %w", err)
	}
	fmt.Print("validating ... ")
	if apfs.ValidateChecksum(omapRootData) {
		fmt.Println("OK.")
	} else {
		fmt.Println("FAILED.")
	}
	fmt.Println()

	// Create IOHandle and ObjectMapBTree for OID resolution
	ioHandle, err := apfs.NewIOHandle()
	if err != nil {
		return fmt.Errorf("failed to create IO handle: %w", err)
	}
	ioHandle.BlockSize = blockSize

	volumeOmap, err := apfs.NewObjectMapBTree(ioHandle, nil, omapRoot)
	if err != nil {
		return fmt.Errorf("failed to create object map B-tree: %w", err)
	}

	// Start interactive exploration
	return exploreTree(file, fsRootData, volumeOmap, blockSize)
}

func readBlock(file io.ReaderAt, blockAddr uint64, blockSize uint32) ([]byte, error) {
	data := make([]byte, blockSize)
	offset := int64(blockAddr) * int64(blockSize)
	if _, err := file.ReadAt(data, offset); err != nil {
		return nil, err
	}
	return data, nil
}

func exploreTree(file io.ReaderAt, nodeData []byte, volumeOmap *apfs.ObjectMapBTree, blockSize uint32) error {
	reader := bufio.NewReader(os.Stdin)
	currentData := nodeData

	for {
		// Parse node using apfs library
		node := apfs.NewBTreeNode()
		if err := node.ReadData(currentData); err != nil {
			return fmt.Errorf("unable to parse B-tree node: %w", err)
		}

		// Display node details
		fmt.Println("\nNode details:")
		fmt.Println(strings.Repeat("-", 80))
		printNodeInfo(currentData, node)
		fmt.Println(strings.Repeat("-", 80))
		fmt.Println()

		numEntries := node.NumberOfEntries()
		if numEntries == 0 {
			fmt.Println("Node has no entries.")
			return nil
		}

		fmt.Printf("\nNode has %d entries, as follows:\n", numEntries)

		// Display all entries
		for i := 0; i < numEntries; i++ {
			entry, err := node.EntryByIndex(i)
			if err != nil {
				continue
			}
			printEntry(i, entry, node.IsLeafNode(), currentData, volumeOmap, file, blockSize)
		}

		// Prompt for entry selection
		fmt.Printf("Choose an entry [0-%d]: ", numEntries-1)
		input, err := reader.ReadString('\n')
		if err != nil {
			return err
		}

		input = strings.TrimSpace(input)
		idx, err := strconv.Atoi(input)
		if err != nil || idx < 0 || idx >= numEntries {
			fmt.Printf("Invalid choice; choose an entry [0-%d]\n", numEntries-1)
			continue
		}

		selectedEntry, _ := node.EntryByIndex(idx)

		// If leaf node, display record and exit
		if node.IsLeafNode() {
			fmt.Println()
			printFSRecord(selectedEntry)
			return nil
		}

		// Else descend to child node
		if len(selectedEntry.ValueData) < 8 {
			return fmt.Errorf("invalid child node pointer")
		}

		childVirtualOID := binary.LittleEndian.Uint64(selectedEntry.ValueData[0:8])
		fmt.Printf("Child node has Virtual OID %#x.\n", childVirtualOID)

		// Resolve through object map
		maxXID := uint64(0xFFFFFFFFFFFFFFFF)
		descriptor, err := volumeOmap.DescriptorByObjectIdentifier(file, childVirtualOID, maxXID)
		if err != nil || descriptor == nil {
			fmt.Printf("Need to descend to node with Virtual OID %#x, but the object map lists no objects with this Virtual OID.\n", childVirtualOID)
			return nil
		}

		physicalAddr := descriptor.Value.ObjectPhysicalAddress
		fmt.Printf("The object map resolved this Virtual OID to block address %#x. Reading ... ", physicalAddr)

		childData, err := readBlock(file, physicalAddr, blockSize)
		if err != nil {
			return fmt.Errorf("failed to read child node: %w", err)
		}

		fmt.Print("validating ... ")
		if apfs.ValidateChecksum(childData) {
			fmt.Println("OK.")
		} else {
			fmt.Println("FAILED.")
		}

		// Continue with child node
		currentData = childData
	}
}

func printNodeInfo(data []byte, node *apfs.BTreeNode) {
	oid := binary.LittleEndian.Uint64(data[8:16])
	xid := binary.LittleEndian.Uint64(data[16:24])

	fmt.Printf("  Object identifier:      %#x\n", oid)
	fmt.Printf("  Transaction identifier: %#x\n", xid)
	fmt.Printf("  Object type:            %#x\n", node.ObjectType)
	fmt.Printf("  Object subtype:         %#x\n", node.ObjectSubtype)

	if node.NodeHeader != nil {
		fmt.Printf("  Flags:                  %#x (", node.NodeHeader.Flags)
		flags := []string{}
		if node.NodeHeader.IsRoot() {
			flags = append(flags, "ROOT")
		}
		if node.NodeHeader.IsLeaf() {
			flags = append(flags, "LEAF")
		}
		if node.NodeHeader.HasFixedKVSize() {
			flags = append(flags, "FIXED_KV_SIZE")
		}
		fmt.Printf("%s)\n", strings.Join(flags, " | "))

		fmt.Printf("  Level:                  %d\n", node.NodeHeader.Level)
		fmt.Printf("  Key count:              %d\n", node.NodeHeader.NumberOfKeys)
	}
}

func printEntry(idx int, entry *apfs.BTreeEntry, isLeaf bool, nodeData []byte, volumeOmap *apfs.ObjectMapBTree, file io.ReaderAt, blockSize uint32) {
	if len(entry.KeyData) < 8 {
		fmt.Printf("- %3d:  Invalid key\n", idx)
		return
	}

	objIDAndType := binary.LittleEndian.Uint64(entry.KeyData[0:8])
	objID := objIDAndType & 0x0FFFFFFFFFFFFFFF
	objType := uint8((objIDAndType >> 60) & 0xF)

	fmt.Printf("- %3d:  %#15x = Virtual OID   ||   %2d = %#x = Type", idx, objID, objType, objType)

	if isLeaf {
		// Leaf node - show record type info
		if objType == 9 && len(entry.ValueData) >= 8 { // DIR_REC
			fileID := binary.LittleEndian.Uint64(entry.ValueData[0:8])
			name := extractDirRecName(entry.KeyData)
			fmt.Printf(" = `dentry`   ||   Dentry Virtual OID = %#16x   ||   Dentry name = %s", fileID, name)
		}
	} else {
		// Branch node - resolve child OID
		if len(entry.ValueData) >= 8 {
			childOID := binary.LittleEndian.Uint64(entry.ValueData[0:8])
			fmt.Printf("   ||   Target child node Virtual OID = %#16x", childOID)

			maxXID := uint64(0xFFFFFFFFFFFFFFFF)
			descriptor, err := volumeOmap.DescriptorByObjectIdentifier(file, childOID, maxXID)
			if err != nil || descriptor == nil {
				fmt.Print("  ||  UNRESOLVABLE")
			} else {
				fmt.Printf("  ||  maps to: %#9x", descriptor.Value.ObjectPhysicalAddress)
			}
		}
	}

	fmt.Println()
}

func extractDirRecName(keyData []byte) string {
	// j_drec_hashed_key_t: hdr(8) + name_len_and_hash(4) + name(variable)
	if len(keyData) > 12 {
		nameBytes := keyData[12:]
		for i, b := range nameBytes {
			if b == 0 {
				return string(nameBytes[:i])
			}
		}
		return string(nameBytes)
	}
	return ""
}

func printFSRecord(entry *apfs.BTreeEntry) {
	if len(entry.KeyData) < 8 {
		fmt.Println("Invalid record")
		return
	}

	objIDAndType := binary.LittleEndian.Uint64(entry.KeyData[0:8])
	objType := uint8((objIDAndType >> 60) & 0xF)

	// For fixed-size keys, type is 0x0 and we need to look at the value
	if objType == 0x0 && len(entry.KeyData) == 8 {
		// This is likely a fixed-size B-tree with plain OID keys
		// Try to infer type from value data structure
		objType = inferTypeFromValue(entry.ValueData)
		fmt.Printf("Key (plain OID):    %#016x\n", objIDAndType)
	} else {
		fmt.Printf("Key (ID and type):  %#016x\n", objIDAndType)
	}

	fmt.Printf("Key size:           %d bytes\n", len(entry.KeyData))
	fmt.Printf("Value size:         %d bytes\n", len(entry.ValueData))
	fmt.Println()

	typeName := apfs.FileSystemRecordTypeName(objType)
	fmt.Printf("Record type: %s\n", typeName)

	// Display type-specific details
	switch objType {
	case 0x3: // INODE
		printInodeRecord(entry)
	case 0x9: // DIR_REC
		printDirRecRecord(entry)
	case 0x8: // FILE_EXTENT
		printFileExtentRecord(entry)
	default:
		fmt.Printf("\nDetailed display not implemented for type %s\n", typeName)
	}
}

// inferTypeFromValue attempts to determine the record type from value structure
func inferTypeFromValue(valueData []byte) uint8 {
	if len(valueData) < 8 {
		return 0x0 // APFS_TYPE_ANY
	}

	// Check if this looks like an inode value (should be at least 92 bytes)
	if len(valueData) >= 92 {
		// Check for reasonable mode value at offset 88-90
		mode := binary.LittleEndian.Uint16(valueData[88:90])
		// File modes are typically in range 0-0177777 (octal)
		if mode > 0 {
			return 0x3 // APFS_TYPE_INODE
		}
	}

	// Check if this looks like a directory entry record (has file_id field)
	if len(valueData) >= 16 {
		fileID := binary.LittleEndian.Uint64(valueData[8:16])
		// If file_id is non-zero and reasonable, might be dir record
		if fileID > 0 && fileID < 0x100000000 {
			return 0x9 // APFS_TYPE_DIR_REC (tentative)
		}
	}

	return 0x0 // APFS_TYPE_ANY - unknown
}

func printInodeRecord(entry *apfs.BTreeEntry) {
	if len(entry.ValueData) < 92 {
		fmt.Println("Value too short for inode")
		return
	}

	fmt.Println("\n=== INODE RECORD ===")
	parentID := binary.LittleEndian.Uint64(entry.ValueData[0:8])
	privateID := binary.LittleEndian.Uint64(entry.ValueData[8:16])
	mode := binary.LittleEndian.Uint16(entry.ValueData[88:90])

	fmt.Printf("  Parent ID:              %#x\n", parentID)
	fmt.Printf("  Private ID:             %#x\n", privateID)
	fmt.Printf("  Mode:                   %#o\n", mode)
}

func printDirRecRecord(entry *apfs.BTreeEntry) {
	fmt.Println("\n=== DIRECTORY RECORD ===")
	name := extractDirRecName(entry.KeyData)
	fmt.Printf("  Name:                   %s\n", name)

	if len(entry.ValueData) >= 8 {
		fileID := binary.LittleEndian.Uint64(entry.ValueData[0:8])
		fmt.Printf("  File ID:                %#x\n", fileID)
	}
}

func printFileExtentRecord(entry *apfs.BTreeEntry) {
	fmt.Println("\n=== FILE EXTENT RECORD ===")

	if len(entry.KeyData) >= 16 {
		logicalAddr := binary.LittleEndian.Uint64(entry.KeyData[8:16])
		fmt.Printf("  Logical address:        %#x\n", logicalAddr)
	}

	if len(entry.ValueData) >= 16 {
		lenAndFlags := binary.LittleEndian.Uint64(entry.ValueData[0:8])
		physBlockNum := binary.LittleEndian.Uint64(entry.ValueData[8:16])
		length := lenAndFlags & 0x00FFFFFFFFFFFFFF

		fmt.Printf("  Length:                 %d bytes\n", length)
		fmt.Printf("  Physical block:         %#x\n", physBlockNum)
	}
}

// resolveVolumeTreeRoots parses the container on a partition-relative reader
// and returns the physical block addresses of the selected volume's
// file-system tree root and object-map tree root.
func resolveVolumeTreeRoots(file io.ReaderAt) (fsAddr, omapAddr uint64, err error) {
	container, err := apfs.Open(file, nil)
	if err != nil {
		return 0, 0, err
	}
	defer container.Close()

	volume, err := container.VolumeBySelector(opts.Volume)
	if err != nil {
		return 0, 0, err
	}

	if volume.ObjectMapBTree == nil || volume.FileSystemBTree == nil {
		return 0, 0, fmt.Errorf("volume trees not initialized")
	}

	omapAddr = volume.ObjectMapBTree.RootNodeOID

	descriptor, err := volume.ObjectMapBTree.DescriptorByObjectIdentifier(
		file,
		volume.FileSystemBTree.RootNodeOID,
		volume.FileSystemBTree.VolumeTransactionID,
	)
	if err != nil {
		return 0, 0, fmt.Errorf("unable to resolve fs-tree root: %w", err)
	}
	if descriptor == nil {
		return 0, 0, fmt.Errorf("fs-tree root OID not found in object map")
	}

	return descriptor.Value.ObjectPhysicalAddress, omapAddr, nil
}
