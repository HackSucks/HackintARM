// apfs inspect IMAGE [SECTION] — low-level structural inspection.
package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var (
	inspectFSTreeRoot uint64
	inspectOmapRoot   uint64
)

var inspectCmd = &cobra.Command{
	Use:   "inspect IMAGE [block N | fstree]",
	Short: "Low-level structural inspection of a volume",
	Long: `Walk the on-disk structures of an APFS container or HFS+ volume for
debugging and forensics. Text output only. The file system is detected
automatically.

Modes:
  inspect IMAGE            structural walk (the default). For APFS: superblock,
                           checkpoints, object maps, volumes. For HFS+: volume
                           header, special files and their B-tree headers.
  inspect IMAGE block N    decode one block by physical address (N accepts
                           decimal or 0x hex). APFS only.
  inspect IMAGE fstree     interactively explore the file-system tree
                           (tree roots are resolved automatically). APFS only.

Examples:
  apfs inspect image.dmg
  apfs inspect hfs.dmg
  apfs inspect image.dmg block 0
  apfs inspect image.dmg block 0x1b0c1
  apfs inspect image.dmg fstree`,
	Args: rangeArgs(1, 3, "IMAGE [block N | fstree]"),
	RunE: runInspect,
}

func init() {
	inspectCmd.Flags().Uint64Var(&inspectFSTreeRoot, "fstree-root", 0,
		"fstree mode: override the physical address of the file-system tree root")
	inspectCmd.Flags().Uint64Var(&inspectOmapRoot, "omap-root", 0,
		"fstree mode: override the physical address of the object map tree root")
}

func runInspect(cmd *cobra.Command, args []string) error {
	imagePath := args[0]

	if opts.Output == "json" {
		return usageErrorf("inspect produces text output only")
	}

	kind, err := detectFileSystem(imagePath)
	if err != nil {
		return err
	}

	// HFS+ has no container, checkpoints or object map, so the block and
	// fstree modes have nothing to decode. Say which mode is missing rather
	// than reporting the file system as unsupported outright.
	if kind == "hfsplus" {
		if len(args) > 1 {
			return withCode(ExitUnsupported,
				fmt.Errorf("inspect %s is APFS-only; HFS+ supports the structural walk (apfs inspect %s)", args[1], imagePath))
		}
		return runInspectHFSPlus(imagePath, opts.Verbose)
	}

	if len(args) == 1 {
		volumeIndex := -1
		if opts.Volume != "" {
			index, err := strconv.Atoi(opts.Volume)
			if err != nil {
				return usageErrorf("inspect selects volumes by index: %v", err)
			}
			volumeIndex = index
		}
		return runInspectWalk(imagePath, volumeIndex, opts.Verbose)
	}

	switch args[1] {
	case "block":
		if len(args) != 3 {
			return usageErrorf("expected: inspect IMAGE block N")
		}
		blockAddr, err := strconv.ParseUint(strings.TrimPrefix(args[2], "0x"), addrBase(args[2]), 64)
		if err != nil {
			return usageErrorf("invalid block address %q: %v", args[2], err)
		}
		return runInspectBlock(imagePath, blockAddr, opts.Verbose)

	case "fstree":
		return runInspectFSTree(imagePath, inspectFSTreeRoot, inspectOmapRoot)

	default:
		return usageErrorf("unknown inspect mode %q (expected: block or fstree)", args[1])
	}
}

func addrBase(s string) int {
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		return 16
	}
	return 10
}
