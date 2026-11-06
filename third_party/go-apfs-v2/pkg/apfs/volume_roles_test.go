package apfs

import (
	"testing"
)

// TestVolumeRoleNaming pins the decoding of apfs_role. The case that matters
// most is 0x00C0: it is APFS_VOL_ROLE_UPDATE (3 << VolumeRoleEnumShift), but
// read as bits it is exactly VolumeRoleData|VolumeRoleBaseband. Roles are a
// single value matched exactly, never a bit field, which is what makes the
// shifted encoding unambiguous.
func TestVolumeRoleNaming(t *testing.T) {
	cases := []struct {
		name  string
		role  uint16
		valid bool
		want  string
		token string
	}{
		{"none", 0x0000, true, "", ""},
		{"system", VolumeRoleSystem, true, "System", "system"},
		{"user", VolumeRoleUser, true, "User", "user"},
		{"recovery", VolumeRoleRecovery, true, "Recovery", "recovery"},
		{"vm", VolumeRoleVM, true, "VM", "vm"},
		{"preboot", VolumeRolePreboot, true, "Preboot", "preboot"},
		{"installer", VolumeRoleInstaller, true, "Installer", "installer"},

		{"data is enum value 1", VolumeRoleData, true, "Data", "data"},
		{"baseband is enum value 2", VolumeRoleBaseband, true, "Baseband", "baseband"},
		{"update is enum value 3, not data|baseband", 0x00C0, true, "Update", "update"},
		{"xart", VolumeRoleXART, true, "XART", "xart"},
		{"enterprise", VolumeRoleEnterprise, true, "Enterprise", "enterprise"},
		{"prelogin is the top defined value", VolumeRolePrelogin, true, "Prelogin", "prelogin"},

		// Roles are never combined; these are not legal apfs_role values, and
		// a checker rejects an image carrying one. Report them honestly rather
		// than inventing a reading.
		{"system|data is not a role", VolumeRoleSystem | VolumeRoleData, false, "Unknown (0x0041)", "unknown-0x0041"},
		{"undefined enum is surfaced, not dropped", 12 << VolumeRoleEnumShift, false, "Unknown (0x0300)", "unknown-0x0300"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsValidVolumeRole(tc.role); got != tc.valid {
				t.Errorf("IsValidVolumeRole(%#04x) = %v, want %v", tc.role, got, tc.valid)
			}
			if got := VolumeRoleName(tc.role); got != tc.want {
				t.Errorf("VolumeRoleName(%#04x) = %q, want %q", tc.role, got, tc.want)
			}
			if got := VolumeRoleString(tc.role); got != tc.token {
				t.Errorf("VolumeRoleString(%#04x) = %q, want %q", tc.role, got, tc.token)
			}
		})
	}
}

// TestVolumeRoleEnumEncoding guards the shift itself: every role above the
// shift must be its enumeration index shifted by VolumeRoleEnumShift.
func TestVolumeRoleEnumEncoding(t *testing.T) {
	shifted := map[uint16]uint16{
		1: VolumeRoleData, 2: VolumeRoleBaseband, 3: VolumeRoleUpdate,
		4: VolumeRoleXART, 5: VolumeRoleHardware, 6: VolumeRoleBackup,
		7: VolumeRoleReserved7, 8: VolumeRoleReserved8, 9: VolumeRoleEnterprise,
		10: VolumeRoleReserved10, 11: VolumeRolePrelogin,
	}
	for index, value := range shifted {
		if want := index << VolumeRoleEnumShift; value != want {
			t.Errorf("enum %d encodes as %#04x, want %#04x", index, value, want)
		}
	}
	const lowMask = VolumeRoleSystem | VolumeRoleUser | VolumeRoleRecovery |
		VolumeRoleVM | VolumeRolePreboot | VolumeRoleInstaller
	if lowMask != 0x003F {
		t.Errorf("low roles cover %#04x, want 0x003f (the six values below the shift)", lowMask)
	}
}

func TestParseVolumeRole(t *testing.T) {
	cases := []struct {
		value string
		want  uint16
		ok    bool
	}{
		{"system", VolumeRoleSystem, true},
		{"SYSTEM", VolumeRoleSystem, true},
		{"  data  ", VolumeRoleData, true},
		{"update", VolumeRoleUpdate, true},
		{"prelogin", VolumeRolePrelogin, true},
		{"none", VolumeRoleNone, true},
		{"", VolumeRoleNone, true},
		{"system+data", 0, false}, // roles are not combined
		{"banana", 0, false},
	}

	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			got, err := ParseVolumeRole(tc.value)
			if tc.ok {
				if err != nil {
					t.Fatalf("ParseVolumeRole(%q) = %v, want success", tc.value, err)
				}
				if got != tc.want {
					t.Errorf("ParseVolumeRole(%q) = %#04x, want %#04x", tc.value, got, tc.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("ParseVolumeRole(%q) = %#04x, want an error", tc.value, got)
			}
		})
	}
}

// TestVolumeRoleRoundTrip checks every token ParseVolumeRole accepts survives a
// trip through VolumeRoleString, so the --volume selector, the --role flag and
// the JSON output all speak the same vocabulary.
func TestVolumeRoleRoundTrip(t *testing.T) {
	for _, token := range VolumeRoleTokens() {
		role, err := ParseVolumeRole(token)
		if err != nil {
			t.Errorf("ParseVolumeRole(%q): %v", token, err)
			continue
		}
		if !IsValidVolumeRole(role) {
			t.Errorf("token %q parses to %#04x, which is not a valid role", token, role)
		}
		want := token
		if token == "none" {
			want = "" // no role renders as the empty token
		}
		if got := VolumeRoleString(role); got != want {
			t.Errorf("%q round-tripped to %q", token, got)
		}
	}
}
