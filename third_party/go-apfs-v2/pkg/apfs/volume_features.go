// Volume feature flags and their descriptions
package apfs

import "fmt"

// Volume feature flag constants

// Compatible features (can be ignored by older implementations)
const (
	VolumeFeatureDefragPrerelease     uint64 = 0x0000000000000001
	VolumeFeatureHardlinkMapRecords   uint64 = 0x0000000000000002
	VolumeFeatureDefrag               uint64 = 0x0000000000000004
	VolumeFeatureStrictAtime          uint64 = 0x0000000000000008
	VolumeFeatureVolgrpSystemInoSpace uint64 = 0x0000000000000010
)

// Incompatible features (must be understood by implementation)
const (
	VolumeIncompatCaseInsensitive     uint64 = 0x0000000000000001
	VolumeIncompatDatalessSnaps       uint64 = 0x0000000000000002
	VolumeIncompatEncRolled           uint64 = 0x0000000000000004
	VolumeIncompatNormalizationInsens uint64 = 0x0000000000000008
	VolumeIncompatIncompleteRestore   uint64 = 0x0000000000000010
	VolumeIncompatSealedVolume        uint64 = 0x0000000000000020
)

// FeatureDescription holds a feature flag and its description
type FeatureDescription struct {
	Flag        uint64
	Name        string
	Description string
}

var compatibleFeatures = []FeatureDescription{
	{VolumeFeatureDefragPrerelease, "Defrag Prerelease", "Defragmentation (prerelease)"},
	{VolumeFeatureHardlinkMapRecords, "Hardlink Map Records", "Hardlink map records"},
	{VolumeFeatureDefrag, "Defrag", "Defragmentation"},
	{VolumeFeatureStrictAtime, "Strict Atime", "Strict access time"},
	{VolumeFeatureVolgrpSystemInoSpace, "Volgrp System Ino Space", "Volume group system inode space"},
}

var incompatibleFeatures = []FeatureDescription{
	{VolumeIncompatCaseInsensitive, "Case Insensitive", "Case-insensitive filenames"},
	{VolumeIncompatDatalessSnaps, "Dataless Snapshots", "Dataless snapshots"},
	{VolumeIncompatEncRolled, "Encryption Rolled", "Encryption keys rolled"},
	{VolumeIncompatNormalizationInsens, "Normalization Insensitive", "Normalization-insensitive filenames"},
	{VolumeIncompatIncompleteRestore, "Incomplete Restore", "Incomplete restore"},
	{VolumeIncompatSealedVolume, "Sealed Volume", "Sealed volume"},
}

// CompatibleFeatureNames returns human-readable names of set compatible features
func (v *Volume) CompatibleFeatureNames() ([]string, error) {
	if v == nil {
		return nil, fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return nil, fmt.Errorf("invalid volume - missing superblock")
	}

	var names []string
	flags := v.Superblock.CompatibleFeaturesFlags
	for _, feature := range compatibleFeatures {
		if flags&feature.Flag != 0 {
			names = append(names, feature.Description)
		}
	}
	return names, nil
}

// IncompatibleFeatureNames returns human-readable names of set incompatible features
func (v *Volume) IncompatibleFeatureNames() ([]string, error) {
	if v == nil {
		return nil, fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return nil, fmt.Errorf("invalid volume - missing superblock")
	}

	var names []string
	flags := v.Superblock.IncompatibleFeaturesFlags
	for _, feature := range incompatibleFeatures {
		if flags&feature.Flag != 0 {
			names = append(names, feature.Description)
		}
	}
	return names, nil
}

// ReadOnlyCompatibleFeatureNames returns human-readable names of set read-only compatible features
func (v *Volume) ReadOnlyCompatibleFeatureNames() ([]string, error) {
	if v == nil {
		return nil, fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return nil, fmt.Errorf("invalid volume - missing superblock")
	}

	// Currently no known read-only compatible features are defined in APFS
	return []string{}, nil
}

// IsCaseInsensitive checks if the volume uses case-insensitive filenames
func (v *Volume) IsCaseInsensitive() (bool, error) {
	if v == nil {
		return false, fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return false, fmt.Errorf("invalid volume - missing superblock")
	}

	return (v.Superblock.IncompatibleFeaturesFlags & VolumeIncompatCaseInsensitive) != 0, nil
}

// IsNormalizationInsensitive checks if the volume uses normalization-insensitive filenames
func (v *Volume) IsNormalizationInsensitive() (bool, error) {
	if v == nil {
		return false, fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return false, fmt.Errorf("invalid volume - missing superblock")
	}

	return (v.Superblock.IncompatibleFeaturesFlags & VolumeIncompatNormalizationInsens) != 0, nil
}

// IsSealed checks if the volume is sealed
func (v *Volume) IsSealed() (bool, error) {
	if v == nil {
		return false, fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return false, fmt.Errorf("invalid volume - missing superblock")
	}

	return (v.Superblock.IncompatibleFeaturesFlags & VolumeIncompatSealedVolume) != 0, nil
}

// HasEncryptionKeysRolled checks if the volume's encryption keys have been changed
func (v *Volume) HasEncryptionKeysRolled() (bool, error) {
	if v == nil {
		return false, fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return false, fmt.Errorf("invalid volume - missing superblock")
	}

	return (v.Superblock.IncompatibleFeaturesFlags & VolumeIncompatEncRolled) != 0, nil
}
