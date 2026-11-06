package apfs

import (
	"strings"
	"testing"
)

// roleVolume builds a Volume carrying just enough superblock for the selector
// to match on: a name and a role.
func roleVolume(name string, role uint16) *Volume {
	sb := &VolumeSuperblock{Role: role, volumeName: name}
	copy(sb.VolumeName[:], name)
	return &Volume{Superblock: sb}
}

// TestVolumeByRole covers selecting a volume by role, which is the whole point
// of decoding apfs_role: in a real macOS container "give me the OS volume"
// should not require knowing its name or index.
func TestVolumeByRole(t *testing.T) {
	system := roleVolume("Macintosh HD", VolumeRoleSystem)
	data := roleVolume("Macintosh HD - Data", VolumeRoleData)
	preboot := roleVolume("Preboot", VolumeRolePreboot)
	volumes := []*Volume{system, data, preboot}

	t.Run("selects the matching volume", func(t *testing.T) {
		got, err := volumeByRole(volumes, "system", "system")
		if err != nil {
			t.Fatalf("volumeByRole: %v", err)
		}
		if got != system {
			t.Error("selected the wrong volume")
		}
	})

	t.Run("no match is an error", func(t *testing.T) {
		if _, err := volumeByRole(volumes, "recovery", "recovery"); err == nil {
			t.Fatal("selecting an absent role succeeded")
		}
	})

	t.Run("unknown role is an error", func(t *testing.T) {
		_, err := volumeByRole(volumes, "banana", "role:banana")
		if err == nil {
			t.Fatal("selecting an unknown role succeeded")
		}
		if !strings.Contains(err.Error(), "unknown volume role") {
			t.Errorf("error = %q, want it to name the problem", err)
		}
	})

	t.Run("none is not selectable", func(t *testing.T) {
		if _, err := volumeByRole(volumes, "none", "none"); err == nil {
			t.Fatal(`selecting the "none" role succeeded; it identifies nothing`)
		}
	})

	// A container can legally hold several volumes with the same role — two
	// recovery volumes in a multi-OS container, for instance. Choosing one
	// arbitrarily is the wrong default for a tool used forensically.
	t.Run("ambiguity names the candidates", func(t *testing.T) {
		ambiguous := []*Volume{
			roleVolume("Recovery A", VolumeRoleRecovery),
			roleVolume("Big Sur", VolumeRoleSystem),
			roleVolume("Recovery B", VolumeRoleRecovery),
		}
		_, err := volumeByRole(ambiguous, "recovery", "recovery")
		if err == nil {
			t.Fatal("an ambiguous role selector silently picked a volume")
		}
		for _, want := range []string{"2 volumes", "0 (Recovery A)", "2 (Recovery B)"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %q", err, want)
			}
		}
	})
}
