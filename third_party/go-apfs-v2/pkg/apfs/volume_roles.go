// Volume roles (apfs_role) and their names.
//
// A volume's role is what makes a multi-volume container legible: without it a
// macOS installer or system image presents as N similarly-named volumes with no
// indication which one holds the OS.
package apfs

import (
	"fmt"
	"sort"
	"strings"
)

// VolumeRoleEnumShift is APFS_VOLUME_ENUM_SHIFT: the bit position at or above
// which a role is encoded as a small enumeration rather than as one of the
// low-numbered values.
const VolumeRoleEnumShift = 6

// Volume roles. Although the low six values are written as single bits, a
// volume's role is a single value and not a bit field — roles are never
// combined, and every checker matches apfs_role against these values exactly.
// That is also why the values at or above VolumeRoleEnumShift are safe:
// VolumeRoleUpdate is 3 << 6 = 0x00c0, which as bits would read as
// VolumeRoleData|VolumeRoleBaseband but as a value is simply "update".
const (
	VolumeRoleNone      uint16 = 0x0000
	VolumeRoleSystem    uint16 = 0x0001
	VolumeRoleUser      uint16 = 0x0002
	VolumeRoleRecovery  uint16 = 0x0004
	VolumeRoleVM        uint16 = 0x0008
	VolumeRolePreboot   uint16 = 0x0010
	VolumeRoleInstaller uint16 = 0x0020

	VolumeRoleData       uint16 = 1 << VolumeRoleEnumShift  // 0x0040
	VolumeRoleBaseband   uint16 = 2 << VolumeRoleEnumShift  // 0x0080
	VolumeRoleUpdate     uint16 = 3 << VolumeRoleEnumShift  // 0x00c0
	VolumeRoleXART       uint16 = 4 << VolumeRoleEnumShift  // 0x0100
	VolumeRoleHardware   uint16 = 5 << VolumeRoleEnumShift  // 0x0140
	VolumeRoleBackup     uint16 = 6 << VolumeRoleEnumShift  // 0x0180
	VolumeRoleReserved7  uint16 = 7 << VolumeRoleEnumShift  // 0x01c0
	VolumeRoleReserved8  uint16 = 8 << VolumeRoleEnumShift  // 0x0200
	VolumeRoleEnterprise uint16 = 9 << VolumeRoleEnumShift  // 0x0240
	VolumeRoleReserved10 uint16 = 10 << VolumeRoleEnumShift // 0x0280
	VolumeRolePrelogin   uint16 = 11 << VolumeRoleEnumShift // 0x02c0
)

// RoleDescription holds one volume role, the token used to select it on the
// command line, and a human-readable name.
type RoleDescription struct {
	Value uint16
	Token string
	Name  string
}

// volumeRoles are every role the format defines, in ascending value order.
// A role not in this table is not a legal apfs_role.
var volumeRoles = []RoleDescription{
	{VolumeRoleNone, "none", "None"},
	{VolumeRoleSystem, "system", "System"},
	{VolumeRoleUser, "user", "User"},
	{VolumeRoleRecovery, "recovery", "Recovery"},
	{VolumeRoleVM, "vm", "VM"},
	{VolumeRolePreboot, "preboot", "Preboot"},
	{VolumeRoleInstaller, "installer", "Installer"},
	{VolumeRoleData, "data", "Data"},
	{VolumeRoleBaseband, "baseband", "Baseband"},
	{VolumeRoleUpdate, "update", "Update"},
	{VolumeRoleXART, "xart", "XART"},
	{VolumeRoleHardware, "hardware", "Hardware"},
	{VolumeRoleBackup, "backup", "Backup"},
	{VolumeRoleReserved7, "reserved-7", "Reserved (7)"},
	{VolumeRoleReserved8, "reserved-8", "Reserved (8)"},
	{VolumeRoleEnterprise, "enterprise", "Enterprise"},
	{VolumeRoleReserved10, "reserved-10", "Reserved (10)"},
	{VolumeRolePrelogin, "prelogin", "Prelogin"},
}

// LookupVolumeRole returns the description of a raw apfs_role value, and
// whether the value is one the format defines.
func LookupVolumeRole(role uint16) (RoleDescription, bool) {
	for _, r := range volumeRoles {
		if r.Value == role {
			return r, true
		}
	}
	return RoleDescription{}, false
}

// IsValidVolumeRole reports whether a raw apfs_role value is one the format
// defines. Combinations are not valid: a volume has exactly one role.
func IsValidVolumeRole(role uint16) bool {
	_, ok := LookupVolumeRole(role)
	return ok
}

// VolumeRoleName returns the human-readable name of a raw apfs_role value, or
// "" when the volume has no role. A value the format does not define is
// rendered as its number rather than dropped — forensic tooling needs to see
// that something was there, and Apple may define values this build predates.
func VolumeRoleName(role uint16) string {
	if role == VolumeRoleNone {
		return ""
	}
	if desc, ok := LookupVolumeRole(role); ok {
		return desc.Name
	}
	return fmt.Sprintf("Unknown (%#04x)", role)
}

// VolumeRoleString returns a lowercase token naming a raw apfs_role value,
// suitable for JSON output and the --volume selector, or "" when the volume has
// no role.
func VolumeRoleString(role uint16) string {
	if role == VolumeRoleNone {
		return ""
	}
	if desc, ok := LookupVolumeRole(role); ok {
		return desc.Token
	}
	return fmt.Sprintf("unknown-%#04x", role)
}

// ParseVolumeRole maps a role token, as VolumeRoleString produces, to its
// apfs_role value. Matching is case-insensitive. An empty string means no role.
func ParseVolumeRole(s string) (uint16, error) {
	trimmed := strings.ToLower(strings.TrimSpace(s))
	if trimmed == "" {
		return VolumeRoleNone, nil
	}
	for _, r := range volumeRoles {
		if r.Token == trimmed {
			return r.Value, nil
		}
	}
	return 0, fmt.Errorf("unknown volume role %q (known roles: %s)", s, strings.Join(VolumeRoleTokens(), ", "))
}

// VolumeRoleTokens returns every role token ParseVolumeRole accepts, sorted,
// for use in help text and error messages.
func VolumeRoleTokens() []string {
	tokens := make([]string, 0, len(volumeRoles))
	for _, r := range volumeRoles {
		tokens = append(tokens, r.Token)
	}
	sort.Strings(tokens)
	return tokens
}

// Role returns the volume's raw apfs_role value.
func (v *Volume) Role() (uint16, error) {
	if v == nil {
		return 0, fmt.Errorf("invalid volume")
	}
	if v.Superblock == nil {
		return 0, fmt.Errorf("invalid volume - missing superblock")
	}
	return v.Superblock.Role, nil
}

// RoleName returns the human-readable name of the volume's role, or "" when it
// has none.
func (v *Volume) RoleName() (string, error) {
	role, err := v.Role()
	if err != nil {
		return "", err
	}
	return VolumeRoleName(role), nil
}

// RoleString returns a lowercase token naming the volume's role, or "" when it
// has none.
func (v *Volume) RoleString() (string, error) {
	role, err := v.Role()
	if err != nil {
		return "", err
	}
	return VolumeRoleString(role), nil
}

// VolumeGroupIdentifier returns the identifier of the volume group this volume
// belongs to (apfs_volume_group_id). The zero UUID means it belongs to none.
func (v *Volume) VolumeGroupIdentifier() ([16]byte, error) {
	if v == nil {
		return [16]byte{}, fmt.Errorf("invalid volume")
	}
	if v.Superblock == nil {
		return [16]byte{}, fmt.Errorf("invalid volume - missing superblock")
	}
	return v.Superblock.VolumeGroupID, nil
}

// IsInVolumeGroup reports whether the volume belongs to a volume group — the
// System/Data pairing macOS has used since Catalina.
//
// Membership is declared by the APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE feature
// flag, not by the group identifier: that flag is what checkers consult, and a
// volume carrying a group identifier without it is malformed.
func (v *Volume) IsInVolumeGroup() (bool, error) {
	if v == nil {
		return false, fmt.Errorf("invalid volume")
	}
	if v.Superblock == nil {
		return false, fmt.Errorf("invalid volume - missing superblock")
	}
	return v.Superblock.CompatibleFeaturesFlags&VolumeFeatureVolgrpSystemInoSpace != 0, nil
}
