package cli

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestParseUUIDFlag(t *testing.T) {
	canonical := [16]byte{0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55}

	cases := []struct {
		name  string
		value string
		want  [16]byte
		ok    bool
	}{
		{"canonical", "11111111-2222-3333-4444-555555555555", canonical, true},
		{"braced", "{11111111-2222-3333-4444-555555555555}", canonical, true},
		{"urn", "urn:uuid:11111111-2222-3333-4444-555555555555", canonical, true},
		{"unhyphenated", "11111111222233334444555555555555", canonical, true},
		{"surrounding space", "  11111111-2222-3333-4444-555555555555 ", canonical, true},
		{"all zero", "00000000-0000-0000-0000-000000000000", [16]byte{}, false},
		{"garbage", "not-a-uuid", [16]byte{}, false},
		{"empty", "", [16]byte{}, false},
		{"truncated", "11111111-2222-3333-4444", [16]byte{}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseUUIDFlag("--uuid", tc.value)
			if tc.ok {
				if err != nil {
					t.Fatalf("parseUUIDFlag(%q) = %v, want success", tc.value, err)
				}
				if got != tc.want {
					t.Errorf("parseUUIDFlag(%q) = %x, want %x", tc.value, got, tc.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("parseUUIDFlag(%q) succeeded, want a usage error", tc.value)
			}
			if code := exitCodeFor(err); code != ExitUsage {
				t.Errorf("parseUUIDFlag(%q) exit code = %d, want %d", tc.value, code, ExitUsage)
			}
		})
	}
}

func TestDeriveContainerUUID(t *testing.T) {
	volume := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	got := uuid.UUID(deriveContainerUUID(volume))

	// Stable across runs and builds: the derivation is SHA-1 over a fixed name.
	const want = "8732acdd-3400-59ef-bf39-60ba5e4dd999"
	if got.String() != want {
		t.Errorf("deriveContainerUUID = %s, want %s", got, want)
	}
	if got.Version() != 5 {
		t.Errorf("version = %d, want 5 (RFC 4122 SHA-1)", got.Version())
	}
	if got.Variant() != uuid.RFC4122 {
		t.Errorf("variant = %v, want RFC4122", got.Variant())
	}
	if got == volume {
		t.Error("derived container UUID equals the volume UUID; they must be distinct")
	}

	other := uuid.MustParse("99999999-2222-3333-4444-555555555555")
	if deriveContainerUUID(other) == deriveContainerUUID(volume) {
		t.Error("different volume UUIDs derive the same container UUID")
	}
}

func TestWriteIdentityFlagsResolve(t *testing.T) {
	const volStr = "11111111-2222-3333-4444-555555555555"
	const ctrStr = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	volBytes := [16]byte(uuid.MustParse(volStr))
	ctrBytes := [16]byte(uuid.MustParse(ctrStr))

	t.Run("unset resolves to zero", func(t *testing.T) {
		var f writeIdentityFlags
		container, volume, err := f.resolve()
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if container != ([16]byte{}) || volume != ([16]byte{}) {
			t.Error("unset flags must resolve to zero so the writer applies its own defaults")
		}
		if f.changed() {
			t.Error("changed() is true with no flags set")
		}
	})

	t.Run("uuid derives the container", func(t *testing.T) {
		f := writeIdentityFlags{uuid: volStr}
		container, volume, err := f.resolve()
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if volume != volBytes {
			t.Errorf("volume = %x, want %x", volume, volBytes)
		}
		if container != deriveContainerUUID(volBytes) {
			t.Error("--uuid did not derive the container UUID")
		}
	})

	t.Run("volume-uuid overrides uuid", func(t *testing.T) {
		f := writeIdentityFlags{uuid: ctrStr, volumeUUID: volStr}
		_, volume, err := f.resolve()
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if volume != volBytes {
			t.Errorf("volume = %x, want %x from --volume-uuid", volume, volBytes)
		}
	})

	t.Run("container-uuid overrides the derivation", func(t *testing.T) {
		f := writeIdentityFlags{uuid: volStr, containerUUID: ctrStr}
		container, volume, err := f.resolve()
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if container != ctrBytes {
			t.Errorf("container = %x, want %x", container, ctrBytes)
		}
		if volume != volBytes {
			t.Errorf("volume = %x, want %x", volume, volBytes)
		}
	})

	t.Run("container-uuid alone", func(t *testing.T) {
		f := writeIdentityFlags{containerUUID: ctrStr}
		container, volume, err := f.resolve()
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if container != ctrBytes {
			t.Errorf("container = %x, want %x", container, ctrBytes)
		}
		if volume != ([16]byte{}) {
			t.Error("volume UUID must stay zero when only --container-uuid is given")
		}
	})

	t.Run("volume-only rejects container-uuid", func(t *testing.T) {
		f := writeIdentityFlags{containerUUID: ctrStr}
		if _, err := f.resolveVolumeOnly("HFS+"); err == nil {
			t.Fatal("resolveVolumeOnly accepted --container-uuid")
		} else if code := exitCodeFor(err); code != ExitUsage {
			t.Errorf("exit code = %d, want %d", code, ExitUsage)
		}
	})
}

func TestParseSourceDateEpoch(t *testing.T) {
	cases := []struct {
		value string
		want  time.Time
		ok    bool
	}{
		{"1700000000", time.Unix(1700000000, 0).UTC(), true},
		{"0", time.Unix(0, 0).UTC(), true},
		{"  1700000000\n", time.Unix(1700000000, 0).UTC(), true},
		{"banana", time.Time{}, false},
		{"-1", time.Time{}, false},
		{"1.5", time.Time{}, false},
		{"12abc", time.Time{}, false},
		{"", time.Time{}, false},
		{"2023-11-14T22:13:20Z", time.Time{}, false}, // decimal seconds only
	}

	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			got, err := parseSourceDateEpoch(tc.value)
			if tc.ok {
				if err != nil {
					t.Fatalf("parseSourceDateEpoch(%q) = %v, want success", tc.value, err)
				}
				if !got.Equal(tc.want) {
					t.Errorf("parseSourceDateEpoch(%q) = %s, want %s", tc.value, got, tc.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("parseSourceDateEpoch(%q) succeeded, want a usage error", tc.value)
			}
			if code := exitCodeFor(err); code != ExitUsage {
				t.Errorf("parseSourceDateEpoch(%q) exit code = %d, want %d", tc.value, code, ExitUsage)
			}
		})
	}
}

func TestWriterTimes(t *testing.T) {
	saved := opts
	t.Cleanup(func() { opts = saved })

	opts.SourceDateEpoch = time.Time{}
	if fixed, clamp := writerTimes(); !fixed.IsZero() || clamp {
		t.Error("with no epoch, writerTimes must return the zero time and no clamp so each writer applies its own default")
	}

	epoch := time.Unix(1700000000, 0).UTC()
	opts.SourceDateEpoch = epoch
	fixed, clamp := writerTimes()
	if !fixed.Equal(epoch) {
		t.Errorf("fixed = %s, want %s", fixed, epoch)
	}
	if !clamp {
		t.Error("an epoch must also enable mod-time clamping")
	}
}
