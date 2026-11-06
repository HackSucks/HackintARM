package apfs

import (
	"encoding/binary"
	"testing"
)

// minimalVolumeSuperblock returns a buffer of exactly n bytes carrying the
// object header, type and signature ReadData validates, so a test can set one
// field and parse it. n must be at least 1024.
func minimalVolumeSuperblock(n int) []byte {
	data := make([]byte, n)
	binary.LittleEndian.PutUint32(data[24:28], 0x0000000d) // volume superblock
	binary.LittleEndian.PutUint32(data[28:32], 0)          // subtype
	copy(data[32:36], "APSB")
	return data
}

// TestVolumeSuperblockParsesRoleAndVolumeGroup pins the two fields this build
// added: apfs_role at offset 964 and apfs_volume_group_id at 1008. The group
// identifier ends exactly at the 1024-byte minimum ReadData enforces, so a
// buffer of exactly that length must parse rather than panic.
func TestVolumeSuperblockParsesRoleAndVolumeGroup(t *testing.T) {
	groupID := [16]byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}

	for _, size := range []int{1024, 4096} {
		data := minimalVolumeSuperblock(size)
		binary.LittleEndian.PutUint16(data[964:966], VolumeRoleSystem)
		copy(data[1008:1024], groupID[:])

		vs := NewVolumeSuperblock()
		if err := vs.ReadData(data, false); err != nil {
			t.Fatalf("ReadData(%d bytes): %v", size, err)
		}
		if vs.Role != VolumeRoleSystem {
			t.Errorf("%d bytes: role = %#04x, want %#04x", size, vs.Role, VolumeRoleSystem)
		}
		if vs.VolumeGroupID != groupID {
			t.Errorf("%d bytes: volume group id = %x, want %x", size, vs.VolumeGroupID, groupID)
		}

		got, err := vs.VolumeGroupIdentifier()
		if err != nil {
			t.Fatalf("VolumeGroupIdentifier: %v", err)
		}
		if got != groupID {
			t.Errorf("%d bytes: VolumeGroupIdentifier = %x, want %x", size, got, groupID)
		}
	}
}

// TestVolumeSuperblockRoleOffsetIsNotVolumeName guards against the role being
// read out of the tail of the 256-byte volume name: a name filling its field
// must not bleed into the role or the group identifier.
func TestVolumeSuperblockRoleOffsetIsNotVolumeName(t *testing.T) {
	data := minimalVolumeSuperblock(1024)
	for i := 704; i < 960; i++ {
		data[i] = 'A'
	}
	binary.LittleEndian.PutUint16(data[964:966], VolumeRoleData)

	vs := NewVolumeSuperblock()
	if err := vs.ReadData(data, false); err != nil {
		t.Fatalf("ReadData: %v", err)
	}
	if vs.Role != VolumeRoleData {
		t.Errorf("role = %#04x, want %#04x", vs.Role, VolumeRoleData)
	}
	if vs.VolumeGroupID != ([16]byte{}) {
		t.Errorf("volume group id = %x, want all zero", vs.VolumeGroupID)
	}
}

// TestVolumeSuperblockTooShort confirms a buffer below the minimum is an error
// rather than a panic, now that parsing reaches the last byte of that minimum.
func TestVolumeSuperblockTooShort(t *testing.T) {
	for _, size := range []int{0, 512, 1023} {
		vs := NewVolumeSuperblock()
		if err := vs.ReadData(make([]byte, size), false); err == nil {
			t.Errorf("ReadData(%d bytes) succeeded, want an error", size)
		}
	}
}
