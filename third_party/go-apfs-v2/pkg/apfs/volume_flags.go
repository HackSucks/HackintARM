// Volume status flags (apfs_fs_flags) and what they say about encryption.
package apfs

import "fmt"

// Volume flags, from the volume superblock's apfs_fs_flags field.
const (
	// VolumeFlagUnencrypted means the volume's contents are stored in the
	// clear. Its absence is what marks a FileVault volume: the flag says
	// "unencrypted", so encryption is the default reading of a volume that
	// does not set it.
	VolumeFlagUnencrypted uint64 = 0x00000001
	// VolumeFlagOneKey means the whole volume is encrypted with a single key,
	// rather than a key per file. This is what FileVault produces.
	VolumeFlagOneKey uint64 = 0x00000008
	// VolumeFlagSpilledOver means the volume has run out of space on its
	// Fusion drive's solid-state half and spilled onto the rotational one.
	VolumeFlagSpilledOver uint64 = 0x00000010
	// VolumeFlagRunSpilloverCleaner means the spillover cleaner should run.
	VolumeFlagRunSpilloverCleaner uint64 = 0x00000020
	// VolumeFlagAlwaysCheckExtentref means the extent-reference tree must
	// always be consulted when deciding whether an extent is in use.
	VolumeFlagAlwaysCheckExtentref uint64 = 0x00000040
)

// IsEncrypted reports whether the volume's contents are encrypted.
//
// It is the absence of APFS_FS_UNENCRYPTED that says so, which is worth stating
// because the sense is inverted from what the name suggests: a volume with no
// flags set at all is encrypted.
func (v *Volume) IsEncrypted() (bool, error) {
	if v == nil {
		return false, fmt.Errorf("invalid volume")
	}
	if v.Superblock == nil {
		return false, fmt.Errorf("invalid volume - missing superblock")
	}
	return v.Superblock.VolumeFlags&VolumeFlagUnencrypted == 0, nil
}
