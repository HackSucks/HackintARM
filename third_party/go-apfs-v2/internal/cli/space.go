// Free-space checks for the scratch file an image is built into.
package cli

import (
	"fmt"
	"io/fs"
	"path/filepath"

	diskspace "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/diskspace"
)

// spaceHeadroom is the fraction added to an estimate before checking it, to
// cover the file system metadata and the container overhead an estimate based
// on content alone does not account for.
const spaceHeadroom = 20 // percent

// ensureScratchSpace refuses to start a build that cannot fit.
//
// Building an image writes it twice over: once into the scratch file and once
// into the DMG. Running out part-way leaves a truncated image and a partially
// written scratch file, after however long the build took — so it is worth a
// stat beforehand to fail in the first second instead with a message saying
// what is needed and where to put it.
//
// The check is advisory. When the platform cannot report free space, or the
// size cannot be estimated, the build proceeds: refusing to work because we
// could not measure would be worse than the problem.
func ensureScratchSpace(scratchDir, dstPath string, imageBytes uint64) error {
	if imageBytes == 0 {
		return nil
	}
	available, ok, err := diskspace.AvailableSpace(scratchDir)
	if err != nil || !ok {
		return nil
	}

	if needed := requiredScratchBytes(scratchDir, dstPath, imageBytes); available < needed {
		advice := "free some space"
		if opts.TempDir == "" {
			advice = "free some space, or put the scratch file elsewhere with --temp-dir"
		}
		return withCode(ExitError, fmt.Errorf(
			"not enough space in %s: the build needs about %s and %s is available; %s",
			scratchDir, formatSize(needed), formatSize(available), advice))
	}
	return nil
}

// requiredScratchBytes is how much room a build of imageBytes needs in
// scratchDir. Kept separate from the check so the arithmetic can be tested
// without a full disk.
//
// When --temp-dir puts the scratch file on another file system, only the raw
// image is budgeted for and the destination is not checked at all. That is
// deliberate rather than an oversight: a DMG's size depends on how well its
// contents compress, and a mostly-empty volume compresses to a few kilobytes.
// Budgeting the destination at image size would refuse builds that fit
// comfortably, and false refusals are worse than a late error the encoder will
// report anyway.
func requiredScratchBytes(scratchDir, dstPath string, imageBytes uint64) uint64 {
	needed := imageBytes
	// By default the scratch file sits beside the output, so the raw image and
	// the DMG built from it occupy the same file system at once. The DMG is
	// usually smaller, but incompressible content makes it about the same size,
	// so budget for two.
	if filepath.Clean(scratchDir) == filepath.Clean(filepath.Dir(dstPath)) {
		needed *= 2
	}
	return needed + needed/100*spaceHeadroom
}

// sourceTreeBytes totals the regular-file content under dir, as a lower bound
// on the image a pack will produce. It stats rather than reads, so it is cheap
// even on a large tree.
//
// Entries the walk will skip — device nodes, FIFOs, sockets — are excluded, so
// the figure matches what is actually going to be written. Symbolic links are
// too small to matter.
func sourceTreeBytes(dir string) (uint64, error) {
	var total uint64
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable corner makes the estimate low, not wrong enough to
			// abandon it; the build will report the problem properly.
			return nil //nolint:nilerr // deliberate: this is an estimate
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		total += uint64(info.Size())
		return nil
	})
	return total, err
}

// ensureScratchSpaceForTree checks a directory pack will fit, estimating the
// image from the source tree's content.
//
// The estimate is a lower bound: the volume also holds its own metadata, which
// the headroom covers. It is checked before the tree is walked into memory, so
// a build that cannot fit fails immediately rather than after reading
// everything.
func ensureScratchSpaceForTree(srcDir, dstPath string) error {
	bytes, err := sourceTreeBytes(srcDir)
	if err != nil {
		return nil // could not measure: let the build proceed and report properly
	}
	return ensureScratchSpace(scratchDir(dstPath), dstPath, bytes)
}
