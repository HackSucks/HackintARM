// Wires APFS directory packing (pack <dir> --fs apfs) into the CLI via the
// pure-Go pkg/apfswrite builder.
package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

// packDirectoryAPFS builds an APFS container from srcDir and wraps it in a DMG.
func packDirectoryAPFS(ctx context.Context, srcDir, dstPath, volname string, encOpts *disk.EncodeOptions) (result error) {
	containerUUID, volumeUUID, err := packUUIDs.resolve()
	if err != nil {
		return err
	}
	fixed, clamp := writerTimes()

	createOpts := &apfswrite.CreateOptions{
		VolumeName:    volname,
		ContainerUUID: containerUUID,
		VolumeUUID:    volumeUUID,
		FixedTime:     fixed,
		ClampModTimes: clamp,
	}
	if packSnapshot != "" {
		createOpts.Snapshots = []apfswrite.SnapshotSpec{{Name: packSnapshot}}
	}

	// Walk before writing, so --strict can refuse without leaving a file behind.
	tree, err := apfswrite.OpenEntryTreeFromDir(srcDir, &apfswrite.WalkOptions{
		Context:      ctx,
		MetadataRoot: packMetadataRoot,
		Xattrs:       true,
		Decompress:   packDecompress,
		Warn:         fidelityWarner(),
	})
	if err != nil {
		return fmt.Errorf("unable to read %s: %w", srcDir, err)
	}
	defer func() { result = errors.Join(result, tree.Close()) }()
	root, report := tree.Root, tree.Report
	if err := enforceStrict(report, packStrict, srcDir); err != nil {
		return err
	}
	createOpts.Root = root

	if err := ensureScratchSpaceForTree(srcDir, dstPath); err != nil {
		return err
	}

	img, err := newScratchImage(dstPath)
	if err != nil {
		return err
	}
	defer img.Close()

	if err := apfswrite.CreateContainer(img, 0, createOpts); err != nil {
		return fmt.Errorf("unable to build APFS container from %s: %w", srcDir, err)
	}
	if err := disk.WrapRawImageDMGFrom(dstPath, img, img.Size(), "Apple_APFS", encOpts); err != nil {
		return fmt.Errorf("unable to write DMG %s: %w", dstPath, err)
	}
	return packReport(srcDir, dstPath, img.Size(), report)
}
