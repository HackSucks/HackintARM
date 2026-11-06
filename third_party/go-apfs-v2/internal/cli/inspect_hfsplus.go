// Structural inspection of an HFS+ volume: the counterpart to inspect_walk.go,
// which walks an APFS container.
//
// HFS+ has no container, checkpoints or object map, so the structures worth
// showing are different: the volume header, the special files that hold the
// three B-trees, and each tree's header record.
package cli

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
)

// runInspectHFSPlus walks an HFS+ volume's on-disk structure.
func runInspectHFSPlus(imagePath string, verbose bool) error {
	fmt.Printf("Opening volume: %s\n\n", imagePath)

	reader, offset, closer, err := disk.OpenWithOffset(imagePath)
	if err != nil {
		return withCode(ExitBadImage, fmt.Errorf("unable to open image: %w", err))
	}
	defer closer.Close()

	var device io.ReaderAt = reader
	if offset != 0 {
		device = io.NewSectionReader(reader, offset, 1<<62)
	}

	volume, err := hfsplus.New(device)
	if err != nil {
		return withCode(ExitBadImage, fmt.Errorf("unable to parse HFS+ volume: %w", err))
	}
	header := volume.Header()

	fmt.Println("╭─ Volume Header (offset 1024) ────────────────────────────────────╮")
	printHFSVolumeHeader(volume, header)
	fmt.Println("╰──────────────────────────────────────────────────────────────────╯")
	fmt.Println()

	fmt.Println("  Special Files")
	fmt.Println()
	blockSize := int64(header.BlockSize)
	for _, sf := range []struct {
		name string
		fork hfsplus.ForkData
		tree bool
	}{
		{"Allocation bitmap", header.AllocationFile, false},
		{"Extents overflow", header.ExtentsFile, true},
		{"Catalog", header.CatalogFile, true},
		{"Attributes", header.AttributesFile, true},
		{"Startup", header.StartupFile, false},
	} {
		printHFSSpecialFile(device, blockSize, sf.name, sf.fork, sf.tree, verbose)
	}
	fmt.Println()

	fmt.Println("  Allocation")
	fmt.Printf("    %-22s %d\n", "Total blocks", header.TotalBlocks)
	fmt.Printf("    %-22s %d\n", "Free blocks", header.FreeBlocks)
	used := uint64(header.TotalBlocks) - uint64(header.FreeBlocks)
	fmt.Printf("    %-22s %d (%s)\n", "Used blocks", used,
		formatBytes(used*uint64(header.BlockSize)))
	fmt.Printf("    %-22s %d bytes\n", "Block size", header.BlockSize)
	fmt.Println()

	return nil
}

func printHFSVolumeHeader(volume *hfsplus.Volume, h hfsplus.VolumeHeader) {
	kind := "HFS+ (case-insensitive)"
	if h.Signature == hfsplus.HFSXSigWord {
		if volume.CaseSensitive() {
			kind = "HFSX (case-sensitive)"
		} else {
			kind = "HFSX (case-insensitive)"
		}
	}

	fmt.Printf("  %-22s %s\n", "Signature", h.Signature)
	fmt.Printf("  %-22s %d\n", "Version", h.Version)
	fmt.Printf("  %-22s %s\n", "Format", kind)
	fmt.Printf("  %-22s %q\n", "Volume name", volume.Name())
	fmt.Printf("  %-22s %#08x\n", "Attributes", h.Attributes)
	fmt.Printf("  %-22s %s\n", "Last mounted by", string(h.LastMountedVersion[:]))
	fmt.Printf("  %-22s %d\n", "Files", h.FileCount)
	fmt.Printf("  %-22s %d\n", "Folders", h.FolderCount)
	fmt.Printf("  %-22s %s\n", "Created", volume.Created().Format("2006-01-02 15:04:05"))
	fmt.Printf("  %-22s %s\n", "Modified", volume.Modified().Format("2006-01-02 15:04:05"))
	if id := volume.UUID(); id != "" {
		fmt.Printf("  %-22s %s\n", "Volume identifier", id)
	}
	fmt.Printf("  %-22s %d\n", "Next catalog id", h.NextCatalogID)
	fmt.Printf("  %-22s %d\n", "Write count", h.WriteCount)
}

// printHFSSpecialFile shows one special file's fork, and for the three that
// hold B-trees, the tree's header record.
func printHFSSpecialFile(device io.ReaderAt, blockSize int64, name string, fork hfsplus.ForkData, isTree, verbose bool) {
	if fork.TotalBlocks == 0 {
		fmt.Printf("    %-22s absent\n", name)
		return
	}

	fmt.Printf("    %-22s %s in %d block(s)\n", name,
		formatBytes(fork.LogicalSize), fork.TotalBlocks)

	if verbose {
		for i, e := range fork.Extents {
			if e.BlockCount == 0 {
				break
			}
			fmt.Printf("      extent %d: start %d, %d block(s)\n", i, e.StartBlock, e.BlockCount)
		}
		fmt.Printf("      clump size: %d\n", fork.ClumpSize)
	}

	if !isTree {
		return
	}

	// The header node sits at the start of the fork's first extent.
	buf := make([]byte, 14+106)
	if _, err := device.ReadAt(buf, int64(fork.Extents[0].StartBlock)*blockSize); err != nil {
		fmt.Printf("      (unable to read the B-tree header: %v)\n", err)
		return
	}
	var bh hfsplus.BTHeaderRec
	if err := binary.Read(bytes.NewReader(buf[14:]), binary.BigEndian, &bh); err != nil {
		fmt.Printf("      (unable to parse the B-tree header: %v)\n", err)
		return
	}

	fmt.Printf("      nodes: %d total, %d free, depth %d, %d bytes each\n",
		bh.TotalNodes, bh.FreeNodes, bh.TreeDepth, bh.NodeSize)
	fmt.Printf("      records: %d, max key %d bytes, compare %s\n",
		bh.LeafRecords, bh.MaxKeyLength, describeKeyCompare(bh.KeyCompareType))
}

// describeKeyCompare names a B-tree key comparison method. Only the catalog
// uses a named one; the extents and attributes trees compare their keys
// numerically and leave this zero.
func describeKeyCompare(t hfsplus.BTHeaderKeyCompareType) string {
	switch t {
	case hfsplus.HFSCaseFolding:
		return "case folding (0xCF)"
	case hfsplus.HFSBinaryCompare:
		return "binary (0xBC)"
	case 0:
		return "numeric (0x00)"
	default:
		return fmt.Sprintf("unknown (%#02x)", uint8(t))
	}
}
