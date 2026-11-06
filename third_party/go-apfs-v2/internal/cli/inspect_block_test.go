package cli

import "testing"

// TestObjectTypeNamesMatchSpec pins the object-type table to the values in the
// "Object Types" section of the Apple File System Reference. The table was
// previously off by one from OBJECT_TYPE_BTREE (0x02) onward, so every
// `apfs inspect block N` printed the wrong type name.
func TestObjectTypeNamesMatchSpec(t *testing.T) {
	spec := map[uint32]string{
		0x00000000: "INVALID",
		0x00000001: "NX_SUPERBLOCK",
		0x00000002: "BTREE",
		0x00000003: "BTREE_NODE",
		0x00000005: "SPACEMAN",
		0x00000006: "SPACEMAN_CAB",
		0x00000007: "SPACEMAN_CIB",
		0x00000008: "SPACEMAN_BITMAP",
		0x00000009: "SPACEMAN_FREE_QUEUE",
		0x0000000a: "EXTENT_LIST_TREE",
		0x0000000b: "OMAP",
		0x0000000c: "CHECKPOINT_MAP",
		0x0000000d: "FS",
		0x0000000e: "FSTREE",
		0x0000000f: "BLOCKREFTREE",
		0x00000010: "SNAPMETATREE",
		0x00000011: "NX_REAPER",
		0x00000012: "NX_REAP_LIST",
		0x00000013: "OMAP_SNAPSHOT",
		0x00000014: "EFI_JUMPSTART",
		0x00000015: "FUSION_MIDDLE_TREE",
		0x00000016: "NX_FUSION_WBC",
		0x00000017: "NX_FUSION_WBC_LIST",
		0x00000018: "ER_STATE",
		0x00000019: "GBITMAP",
		0x0000001a: "GBITMAP_TREE",
		0x0000001b: "GBITMAP_BLOCK",
		0x0000001c: "ER_RECOVERY_BLOCK",
		0x0000001d: "SNAP_META_EXT",
		0x0000001e: "INTEGRITY_META",
		0x0000001f: "FEXT_TREE",
		0x00000020: "RESERVED_20",
		0x000000ff: "TEST",
		0x6b657973: "CONTAINER_KEYBAG", // 'keys'
		0x72656373: "VOLUME_KEYBAG",    // 'recs'
		0x6d6b6579: "MEDIA_KEYBAG",     // 'mkey'
	}
	for value, want := range spec {
		if got := getObjectTypeName(value); got != want {
			t.Errorf("getObjectTypeName(%#x) = %q, want %q", value, got, want)
		}
	}
}

// TestObjectTypeNameIgnoresFlags checks that the type flags in the high half of
// o_type (OBJ_VIRTUAL/OBJ_EPHEMERAL/OBJ_PHYSICAL and friends) do not affect the
// name, since inspect reads o_type straight off disk.
func TestObjectTypeNameIgnoresFlags(t *testing.T) {
	for _, flags := range []uint32{0x00000000, 0x40000000, 0x80000000, 0x20000000} {
		if got := getObjectTypeName(flags | 0x0000000e); got != "FSTREE" {
			t.Errorf("getObjectTypeName(%#x|FSTREE) = %q, want FSTREE", flags, got)
		}
	}
}

// TestObjectSubtypeNameReusesTypeTable checks that a subtype renders as the
// object type it holds. In APFS o_subtype carries an OBJECT_TYPE_* value, so
// printing it as a bare number loses the information.
func TestObjectSubtypeNameReusesTypeTable(t *testing.T) {
	if got := getObjectSubtypeName(0); got != "NONE" {
		t.Errorf("getObjectSubtypeName(0) = %q, want NONE", got)
	}
	if got := getObjectSubtypeName(0x0000000e); got != "FSTREE" {
		t.Errorf("getObjectSubtypeName(FSTREE) = %q, want FSTREE", got)
	}
	if got := getObjectSubtypeName(0x0000000f); got != "BLOCKREFTREE" {
		t.Errorf("getObjectSubtypeName(BLOCKREFTREE) = %q, want BLOCKREFTREE", got)
	}
}
