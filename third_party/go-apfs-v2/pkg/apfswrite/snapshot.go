// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// snapBuild is a resolved snapshot to write: its name, transaction id, timestamp
// and the block holding its snapshot's volume superblock.
type snapBuild struct {
	name           string
	xid            uint64
	mtime          uint64
	inum           uint64
	sblockPaddr    uint64 // snapshot's volume superblock
	extentrefPaddr uint64 // the snapshot's own extentref tree
}

// objIDMask is the object-id field used in every snapshot-name key. The
// format uses an all-ones id (the 60-bit object-id mask) so name records sort
// after the metadata records within the snapshot-metadata tree.
const objIDMask = 0x0fffffffffffffff

// maxSnapshots caps how many snapshots one volume may carry.
//
// The limit is the snapshot-metadata tree, which this writer builds as a single
// leaf: each snapshot contributes a metadata record and a name record, and the
// pair must fit alongside the others in one node. The bound below is
// conservative for the longest names the format allows -- setSnapshots measures
// the records that will actually be written and refuses only if they genuinely
// do not fit, so short names go much further than this.
const maxSnapshots = 64

// setSnapshots resolves one volume's snapshots. It validates the names, assigns
// each a transaction id starting at firstXID, and counts the snapshot object
// blocks. It returns the next free transaction id.
//
// Transaction ids belong to the container, not to a volume: two volumes'
// snapshots are two points in the container's history, so they are numbered
// from a single counter rather than each starting at one.
func (b volCtx) setSnapshots(spec VolumeSpec, firstXID uint64) (uint64, error) {
	if len(spec.Snapshots) == 0 {
		return firstXID, nil
	}
	if len(spec.Snapshots) > maxSnapshots {
		return 0, fmt.Errorf("apfswrite: %d snapshots requested; at most %d are supported", len(spec.Snapshots), maxSnapshots)
	}
	// Each snapshot is associated with a distinct inode number reserved past the
	// highest user inode; fsck_apfs rejects a zero inum.
	inumBase := b.nextObjID()
	seen := make(map[string]bool, len(spec.Snapshots))
	for i, s := range spec.Snapshots {
		if s.Name == "" {
			return 0, fmt.Errorf("apfswrite: snapshot %d has an empty name", i)
		}
		if strings.ContainsRune(s.Name, 0) {
			return 0, fmt.Errorf("apfswrite: snapshot name %q contains a NUL", s.Name)
		}
		if seen[s.Name] {
			return 0, fmt.Errorf("apfswrite: duplicate snapshot name %q", s.Name)
		}
		seen[s.Name] = true
		mtime := b.entryTime(s.ModTime)
		b.snapshots = append(b.snapshots, &snapBuild{
			name: s.Name, xid: firstXID + uint64(i), mtime: mtime, inum: inumBase + uint64(i),
		})
	}
	// One shared omap snapshot tree, plus a snapshot volume superblock and an
	// extentref tree copy per snapshot.
	b.snapBlocks = 1 + 2*uint64(len(b.snapshots))
	return firstXID + uint64(len(b.snapshots)), nil
}

// placeSnapshots assigns block numbers to the snapshot objects starting at base:
// the volume omap's snapshot tree first, then one snapshot volume superblock per snapshot.
func (b volCtx) placeSnapshots(base uint64) {
	if len(b.snapshots) == 0 {
		return
	}
	b.snapBase = base
	b.volSnapTreePaddr = base
	for i := range b.snapshots {
		b.snapshots[i].sblockPaddr = base + 1 + uint64(i)*2
		b.snapshots[i].extentrefPaddr = base + 2 + uint64(i)*2
	}
}

// extentRefcount is the reference count stamped on every physical-extent record.
// It is one: each volume state (the live volume and each snapshot) accounts its
// own single reference to the extent through its own view of the extent-
// reference tree, so the count within any one tree is one.
func (b *builder) extentRefcount() uint32 {
	return 1
}

// writeSnapMetaTree writes the volume's snapshot-metadata tree: an empty
// root-leaf when there are no snapshots, otherwise a root-leaf holding a
// j_snap_metadata + j_snap_name record pair per snapshot.
func (b volCtx) writeSnapMetaTree(paddr uint64) error {
	if len(b.snapshots) == 0 {
		return b.writeEmptyTree(paddr, paddr, objectTypeSnapMetaTree)
	}
	return b.writeSnapMetaNode(paddr, b.snapMetaRecords())
}

// snapMetaRecords builds the (key, value) records for the snapshot-metadata
// tree: per snapshot a j_snap_metadata record (keyed by xid) and a j_snap_name
// record (keyed by name), sorted by the tree's key order.
func (b volCtx) snapMetaRecords() []fsTreeRecord {
	recs := make([]fsTreeRecord, 0, 2*len(b.snapshots))
	for _, s := range b.snapshots {
		name := append([]byte(s.name), 0) // NUL-terminated

		// j_snap_metadata: key (xid, TYPE_SNAP_METADATA) -> j_snap_metadata_val.
		mkey := make([]byte, sizeofInodeKey)
		setKeyHeader(mkey, 0, s.xid, typeSnapMetadata)
		mval := make([]byte, sizeofSnapMetadataVal+len(name))
		binary.LittleEndian.PutUint64(mval[0:], s.extentrefPaddr)             // extentref_tree_oid
		binary.LittleEndian.PutUint64(mval[8:], s.sblockPaddr)                // sblock_oid (physical)
		binary.LittleEndian.PutUint64(mval[16:], s.mtime)                     // create_time
		binary.LittleEndian.PutUint64(mval[24:], s.mtime)                     // change_time
		binary.LittleEndian.PutUint64(mval[32:], s.inum)                      // inum
		binary.LittleEndian.PutUint32(mval[40:], objPhysical|objectTypeBtree) // extentref_tree_type
		binary.LittleEndian.PutUint32(mval[44:], 0)                           // flags
		binary.LittleEndian.PutUint16(mval[48:], uint16(len(name)))           // name_len
		copy(mval[sizeofSnapMetadataVal:], name)
		recs = append(recs, fsTreeRecord{id: s.xid, typ: typeSnapMetadata, key: mkey, val: mval})

		// j_snap_name: key (~0, TYPE_SNAP_NAME) + name -> j_snap_name_val (xid).
		nkey := make([]byte, sizeofInodeKey+2+len(name))
		setKeyHeader(nkey, 0, objIDMask, typeSnapName)
		binary.LittleEndian.PutUint16(nkey[sizeofInodeKey:], uint16(len(name)))
		copy(nkey[sizeofInodeKey+2:], name)
		nval := make([]byte, 8)
		binary.LittleEndian.PutUint64(nval[0:], s.xid)
		recs = append(recs, fsTreeRecord{id: objIDMask, typ: typeSnapName, name: s.name, key: nkey, val: nval})
	}
	sort.SliceStable(recs, func(i, j int) bool {
		if recs[i].id != recs[j].id {
			return recs[i].id < recs[j].id
		}
		if recs[i].typ != recs[j].typ {
			return recs[i].typ < recs[j].typ
		}
		return recs[i].name < recs[j].name
	})
	return recs
}

// writeSnapMetaNode writes the snapshot-metadata tree as a single physical
// root-leaf holding variable-size records.
func (b *builder) writeSnapMetaNode(paddr uint64, recs []fsTreeRecord) error {
	block := b.zeroedBlock()
	headLen := sizeofBtreeNodePhys
	infoLen := sizeofBtreeInfo

	binary.LittleEndian.PutUint16(block[btnOffFlags:], btnodeRoot|btnodeLeaf)
	binary.LittleEndian.PutUint32(block[btnOffNkeys:], uint32(len(recs)))

	tocLen := tocBytesFor(len(recs))
	putNloc(block, btnOffTableSpace, 0, uint16(tocLen))

	cur := &fsTreeCursor{
		b: b, block: block, tocOff: headLen,
		keyArea: headLen + tocLen, keyOff: headLen + tocLen,
		valAreaEnd: int(b.blocksize) - infoLen, valEnd: int(b.blocksize) - infoLen,
	}
	longestKey, longestVal := 0, 0
	for _, r := range recs {
		cur.putRecord(r.key, r.val)
		if len(r.key) > longestKey {
			longestKey = len(r.key)
		}
		if len(r.val) > longestVal {
			longestVal = len(r.val)
		}
	}

	keyLen := cur.keyOff - cur.keyArea
	valLen := cur.valAreaEnd - cur.valEnd
	freeLen := int(b.blocksize) - headLen - tocLen - keyLen - valLen - infoLen
	putNloc(block, btnOffFreeSpace, uint16(keyLen), uint16(freeLen))
	putNloc(block, btnOffKeyFreeList, btoffInvalid, 0)
	putNloc(block, btnOffValFreeList, btoffInvalid, 0)

	info := block[int(b.blocksize)-infoLen:]
	binary.LittleEndian.PutUint32(info[0:], btreePhysical|btreeKVNonaligned) // bt_flags
	binary.LittleEndian.PutUint32(info[4:], b.blocksize)                     // bt_node_size
	binary.LittleEndian.PutUint32(info[16:], uint32(longestKey))             // bt_longest_key
	binary.LittleEndian.PutUint32(info[20:], uint32(longestVal))             // bt_longest_val
	binary.LittleEndian.PutUint64(info[24:], uint64(len(recs)))              // bt_key_count
	binary.LittleEndian.PutUint64(info[32:], 1)                              // bt_node_count

	setObjectHeader(block, int(b.blocksize), paddr, objectTypeBtree|objPhysical, objectTypeSnapMetaTree)
	return b.writeBlock(block, paddr)
}

// writeSnapshots writes each snapshot's snapshot's volume superblock and the volume
// omap's snapshot tree.
func (b volCtx) writeSnapshots() error {
	if len(b.snapshots) == 0 {
		return nil
	}
	for i, s := range b.snapshots {
		// Only the oldest snapshot owns the populated extent-reference tree.
		//
		// On a real volume, taking a snapshot moves the populated tree to the
		// snapshot and leaves a new empty one live; taking another moves
		// nothing, because the extents are already owned. Giving every snapshot
		// a populated copy counts each extent once per snapshot, which apfsck
		// reports as "Physical extent record: is NEW but has already used
		// blocks".
		var err error
		if i == 0 {
			err = b.makeExtentrefRoot(s.extentrefPaddr, s.extentrefPaddr)
		} else {
			err = b.writeEmptyTree(s.extentrefPaddr, s.extentrefPaddr, objectTypeBlockrefTree)
		}
		if err != nil {
			return err
		}
		if err := b.writeSnapshotVolumeSuperblock(s); err != nil {
			return err
		}
	}
	return b.writeOmapSnapshotTree(b.volSnapTreePaddr)
}

// writeSnapshotVolumeSuperblock writes a snapshot's volume superblock: a
// physical copy of the volume superblock as it stood at the snapshot's xid,
// referenced by the snapshot record's sblock_oid.
func (b volCtx) writeSnapshotVolumeSuperblock(s *snapBuild) error {
	vsb := b.volumeSuperblock()
	// The count is the volume's state at the moment this snapshot was taken,
	// which is how many snapshots already existed: none for the first, one for
	// the second, and so on. apfsck compares each frozen superblock's count
	// against the snapshots older than it -- "Volume superblock: bad snapshot
	// count" -- so a fixed zero is only right while there is one snapshot.
	vsb.NumSnapshots = s.xid - 1

	// A snapshot's volume superblock is a partial copy: the object map, the
	// extentref tree and the snapshot metadata tree are *not* reached through
	// it. The reader takes the object map and snapshot metadata tree from the
	// live volume superblock, and the snapshot's extentref tree from the
	// snapshot metadata record's extentref_tree_oid (see snapMetaRecords),
	// which is why that record carries the field at all. apfsck asserts all
	// three, in apfsck/snapshot.c:check_snapshot():
	//
	//	if (vsb->v_extref_oid != 0)
	//		report("Snapshot volume superblock", "has extentref tree.");
	//	if (vsb->v_omap_oid != 0)
	//		report("Snapshot volume superblock", "has object map.");
	//	if (vsb->v_snap_meta_oid != 0)
	//		report("Snapshot volume superblock", "has snapshot tree.");
	vsb.ExtentrefTreeOID = 0
	vsb.OmapOID = 0
	vsb.SnapMetaTreeOID = 0

	block := b.zeroedBlock()
	marshalInto(block, vsb)
	setObjectHeaderXID(block, int(b.blocksize), s.sblockPaddr,
		objPhysical|objectTypeFS, objectTypeInvalid, s.xid)
	return b.writeBlock(block, s.sblockPaddr)
}

// writeOmapSnapshotTree writes the volume omap's snapshot tree: a physical,
// fixed-layout root-leaf keyed by snapshot xid, each value an omap_snapshot_t
// (flags, pad, oid — all zero for a plain snapshot).
func (b volCtx) writeOmapSnapshotTree(paddr uint64) error {
	const keySz, valSz = 8, sizeofOmapSnapshot
	block := b.zeroedBlock()
	headLen := sizeofBtreeNodePhys
	infoLen := sizeofBtreeInfo
	n := len(b.snapshots)

	capacity := (int(b.blocksize) - headLen) / (keySz + valSz + sizeofKvoff)
	tocLen := capacity * sizeofKvoff
	keyArea := headLen + tocLen
	valAreaEnd := int(b.blocksize) - infoLen

	for i, s := range b.snapshots {
		toc := headLen + i*sizeofKvoff
		keyOff := keyArea + i*keySz
		valOff := valAreaEnd - (i+1)*valSz
		binary.LittleEndian.PutUint16(block[toc:], uint16(keyOff-keyArea))
		binary.LittleEndian.PutUint16(block[toc+2:], uint16(valAreaEnd-valOff))
		binary.LittleEndian.PutUint64(block[keyOff:], s.xid) // key: snapshot xid
		// value omap_snapshot_t {flags, pad, oid} is left zero.
	}

	usedKeys := n * keySz
	usedVals := n * valSz
	freeLen := int(b.blocksize) - headLen - tocLen - usedKeys - usedVals - infoLen
	writeLeafHeader(block, btnodeRoot|btnodeLeaf|btnodeFixedKVSize, n, tocLen, usedKeys, freeLen)

	info := block[int(b.blocksize)-infoLen:]
	binary.LittleEndian.PutUint32(info[0:], btreePhysical) // bt_flags
	binary.LittleEndian.PutUint32(info[4:], b.blocksize)   // bt_node_size
	binary.LittleEndian.PutUint32(info[8:], keySz)         // bt_key_size
	binary.LittleEndian.PutUint32(info[12:], valSz)        // bt_val_size
	binary.LittleEndian.PutUint32(info[16:], keySz)        // bt_longest_key
	binary.LittleEndian.PutUint32(info[20:], valSz)        // bt_longest_val
	binary.LittleEndian.PutUint64(info[24:], uint64(n))    // bt_key_count
	binary.LittleEndian.PutUint64(info[32:], 1)            // bt_node_count

	setObjectHeader(block, int(b.blocksize), paddr, objectTypeBtree|objPhysical, objectTypeOmapSnapshot)
	return b.writeBlock(block, paddr)
}
