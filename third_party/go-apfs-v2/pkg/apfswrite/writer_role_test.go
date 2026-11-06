// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite_test

import (
	"os"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

// TestCreateContainerRoleRoundTrip writes a volume carrying each role and reads
// it back through pkg/apfs. Until this existed no fixture had a non-zero role,
// so nothing exercised the decoder against real bytes.
func TestCreateContainerRoleRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		role      uint16
		wantName  string
		wantToken string
	}{
		{"none", apfs.VolumeRoleNone, "", ""},
		{"system", apfs.VolumeRoleSystem, "System", "system"},
		{"data", apfs.VolumeRoleData, "Data", "data"},
		// 0x00c0 is the value a bitwise decode gets wrong, reading it as
		// "Data, Baseband". Prove it survives a real write and read.
		{"update", apfs.VolumeRoleUpdate, "Update", "update"},
		{"preboot", apfs.VolumeRolePreboot, "Preboot", "preboot"},
		{"recovery", apfs.VolumeRoleRecovery, "Recovery", "recovery"},
		{"prelogin", apfs.VolumeRolePrelogin, "Prelogin", "prelogin"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vol := openVolume(t, &apfswrite.CreateOptions{VolumeName: "ROLES", Role: tc.role})

			role, err := vol.Role()
			if err != nil {
				t.Fatalf("Role: %v", err)
			}
			if role != tc.role {
				t.Errorf("role = %#04x, want %#04x", role, tc.role)
			}

			name, err := vol.RoleName()
			if err != nil {
				t.Fatalf("RoleName: %v", err)
			}
			if name != tc.wantName {
				t.Errorf("role name = %q, want %q", name, tc.wantName)
			}

			token, err := vol.RoleString()
			if err != nil {
				t.Fatalf("RoleString: %v", err)
			}
			if token != tc.wantToken {
				t.Errorf("role token = %q, want %q", token, tc.wantToken)
			}
		})
	}
}

// TestCreateContainerVolumeGroupRoundTrip checks the group identifier survives
// a write and read, and that membership is reported from the feature flag the
// writer must set alongside it.
func TestCreateContainerVolumeGroupRoundTrip(t *testing.T) {
	groupID := [16]byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}

	// A group is a system/data pair, so both halves are written; the system
	// one is the volume examined below.
	img := &memImage{}
	err := apfswrite.CreateContainer(img, 1024*1024*1024, &apfswrite.CreateOptions{
		Volumes: []apfswrite.VolumeSpec{
			{Name: "GROUP", Role: apfs.VolumeRoleSystem, VolumeGroupID: groupID},
			{Name: "GROUPDATA", Role: apfs.VolumeRoleData, VolumeGroupID: groupID},
		},
	})
	if err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	container, err := apfs.Open(img, &apfs.OpenOptions{})
	if err != nil {
		t.Fatalf("apfs.Open: %v", err)
	}
	volumes, err := container.Volumes()
	if err != nil {
		t.Fatalf("Volumes: %v", err)
	}
	vol := volumes[0]

	got, err := vol.VolumeGroupIdentifier()
	if err != nil {
		t.Fatalf("VolumeGroupIdentifier: %v", err)
	}
	if got != groupID {
		t.Errorf("volume group id = %x, want %x", got, groupID)
	}

	inGroup, err := vol.IsInVolumeGroup()
	if err != nil {
		t.Fatalf("IsInVolumeGroup: %v", err)
	}
	if !inGroup {
		t.Error("IsInVolumeGroup = false; the writer must set APFS_FEATURE_VOLGRP_SYSTEM_INO_SPACE " +
			"alongside the group identifier, which is what declares membership")
	}
}

// TestCreateContainerNoRoleByDefault confirms the default stays "no role, no
// group, no extra feature flag", so every image this tool already produces is
// unchanged.
func TestCreateContainerNoRoleByDefault(t *testing.T) {
	vol := openVolume(t, &apfswrite.CreateOptions{VolumeName: "PLAIN"})

	role, err := vol.Role()
	if err != nil {
		t.Fatalf("Role: %v", err)
	}
	if role != apfs.VolumeRoleNone {
		t.Errorf("role = %#04x, want none", role)
	}

	group, err := vol.VolumeGroupIdentifier()
	if err != nil {
		t.Fatalf("VolumeGroupIdentifier: %v", err)
	}
	if group != ([16]byte{}) {
		t.Errorf("volume group id = %x, want all zero", group)
	}

	inGroup, err := vol.IsInVolumeGroup()
	if err != nil {
		t.Fatalf("IsInVolumeGroup: %v", err)
	}
	if inGroup {
		t.Error("a volume with no group reports as being in one")
	}
}

// TestCreateContainerRejectsInvalidRole checks the writer refuses combinations
// that would produce an image a checker rejects, rather than writing a
// container that only fails later under apfsck or macOS.
func TestCreateContainerRejectsInvalidRole(t *testing.T) {
	groupID := [16]byte{0xde, 0xad, 0xbe, 0xef}

	cases := []struct {
		name     string
		opts     apfswrite.CreateOptions
		contains string
	}{
		{
			"combined roles",
			apfswrite.CreateOptions{Role: apfs.VolumeRoleSystem | apfs.VolumeRoleData},
			"exactly one role",
		},
		{
			"undefined role",
			apfswrite.CreateOptions{Role: 12 << apfs.VolumeRoleEnumShift},
			"invalid volume role",
		},
		{
			"group member with no role",
			apfswrite.CreateOptions{VolumeGroupID: groupID},
			"must have the system or data role",
		},
		{
			"group member with the wrong role",
			apfswrite.CreateOptions{Role: apfs.VolumeRolePreboot, VolumeGroupID: groupID},
			"must have the system or data role",
		},
		{
			// A group needs both halves. apfsck calls a missing system volume
			// corruption and a missing data volume an oddity; neither is worth
			// writing on purpose.
			"data volume alone in a group",
			apfswrite.CreateOptions{Role: apfs.VolumeRoleData, VolumeGroupID: groupID},
			"has no system volume",
		},
		{
			"system volume alone in a group",
			apfswrite.CreateOptions{Role: apfs.VolumeRoleSystem, VolumeGroupID: groupID},
			"has no data volume",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := apfswrite.CreateContainer(&memImage{}, 32*1024*1024, &tc.opts)
			if err == nil {
				t.Fatal("CreateContainer succeeded, want a validation error")
			}
			if !strings.Contains(err.Error(), tc.contains) {
				t.Errorf("error = %q, want it to mention %q", err, tc.contains)
			}
		})
	}
}

// TestCreateContainerRejectsSpecialEntry checks a caller-built tree containing
// something this writer cannot model is refused rather than silently written
// with the wrong mode. The directory walk skips such files; a caller assembling
// an Entry tree by hand gets told instead.
func TestCreateContainerRejectsSpecialEntry(t *testing.T) {
	for _, mode := range []os.FileMode{
		os.ModeNamedPipe | 0o644,
		os.ModeSocket | 0o644,
		os.ModeDevice | 0o644,
		os.ModeDevice | os.ModeCharDevice | 0o644,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			opts := &apfswrite.CreateOptions{
				VolumeName: "SPECIAL",
				Root: &apfswrite.Entry{Children: []*apfswrite.Entry{
					{Name: "ordinary.txt", Data: []byte("fine\n")},
					{Name: "special", Mode: mode},
				}},
			}
			err := apfswrite.CreateContainer(&memImage{}, 32*1024*1024, opts)
			if err == nil {
				t.Fatalf("CreateContainer accepted a %s entry", mode.Type())
			}
			if !strings.Contains(err.Error(), "regular files, directories and symbolic links") {
				t.Errorf("error = %q, want it to say what the writer can model", err)
			}
		})
	}
}
