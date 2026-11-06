// Wires APFS volume creation (create --fs apfs) into the CLI via the pure-Go
// pkg/apfswrite builder.
package cli

import (
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

func createAPFS(dstPath string, sizeBytes int64) error {
	containerUUID, volumeUUID, err := createUUIDs.resolve()
	if err != nil {
		return err
	}
	role, err := apfs.ParseVolumeRole(createRole)
	if err != nil {
		return usageErrorf("invalid --role: %v", err)
	}
	var volumeGroup [16]byte
	if createVolGroup != "" {
		if volumeGroup, err = parseUUIDFlag("--volume-group", createVolGroup); err != nil {
			return err
		}
		// A volume group is a system/data pair, so asking for one produces both
		// halves. Naming a role as well would be describing only one of them.
		if createRole != "" {
			return usageErrorf("--volume-group and --role cannot be combined: a volume group is a " +
				"system/data pair, so --volume-group creates both halves and gives each its role")
		}
	}
	fixed, clamp := writerTimes()

	createOpts := &apfswrite.CreateOptions{
		VolumeName:    createVolName,
		CaseSensitive: createCaseSens,
		ContainerUUID: containerUUID,
		VolumeUUID:    volumeUUID,
		Role:          role,
		FixedTime:     fixed,
		ClampModTimes: clamp,
	}
	if createSnapshot != "" {
		createOpts.Snapshots = []apfswrite.SnapshotSpec{{Name: createSnapshot}}
	}

	if volumeGroup != ([16]byte{}) {
		// Both halves, named the way macOS names them: the data volume takes
		// the system volume's name with " - Data" appended.
		createOpts.VolumeName = ""
		createOpts.VolumeUUID = [16]byte{}
		createOpts.Role = 0
		createOpts.Snapshots = nil
		createOpts.CaseSensitive = false
		createOpts.Volumes = []apfswrite.VolumeSpec{
			{
				Name:          createVolName,
				UUID:          volumeUUID,
				Role:          apfs.VolumeRoleSystem,
				VolumeGroupID: volumeGroup,
				CaseSensitive: createCaseSens,
			},
			{
				Name:          createVolName + " - Data",
				Role:          apfs.VolumeRoleData,
				VolumeGroupID: volumeGroup,
				CaseSensitive: createCaseSens,
			},
		}
		if createSnapshot != "" {
			createOpts.Volumes[0].Snapshots = []apfswrite.SnapshotSpec{{Name: createSnapshot}}
		}
		// Two volumes need a container the format will accept: one per 512 MiB.
		if minBytes := int64(2) * 512 * 1024 * 1024; sizeBytes < minBytes {
			sizeBytes = minBytes
		}
	}
	if err := ensureScratchSpace(scratchDir(dstPath), dstPath, uint64(sizeBytes)); err != nil {
		return err
	}

	img, err := newScratchImage(dstPath)
	if err != nil {
		return err
	}
	defer img.Close()

	if err := apfswrite.CreateContainer(img, sizeBytes, createOpts); err != nil {
		return fmt.Errorf("unable to create APFS container: %w", err)
	}
	if err := disk.WrapRawImageDMGFrom(dstPath, img, img.Size(), "Apple_APFS", nil); err != nil {
		return fmt.Errorf("unable to write DMG: %w", err)
	}
	return createReport(dstPath, "apfs")
}
