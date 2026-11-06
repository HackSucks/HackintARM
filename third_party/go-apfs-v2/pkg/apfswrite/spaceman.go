// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite

import "encoding/binary"

// Field offsets within an apfs_spaceman_phys object.
const (
	smOffBlockSize       = 0x20
	smOffBlocksPerChunk  = 0x24
	smOffChunksPerCib    = 0x28
	smOffCibsPerCab      = 0x2c
	smOffDev             = 0x30 // sm_dev[APFS_SD_COUNT], 48 bytes each
	smOffFlags           = 0x90
	smOffIPBMTxMult      = 0x94
	smOffIPBlockCount    = 0x98
	smOffIPBMSizeBlocks  = 0xa0
	smOffIPBMBlockCount  = 0xa4
	smOffIPBMBase        = 0xa8
	smOffIPBase          = 0xb0
	smOffFQ              = 0xc8 // sm_fq[APFS_SFQ_COUNT], 40 bytes each
	smOffIPBMFreeHead    = 0x140
	smOffIPBMFreeTail    = 0x142
	smOffIPBMXidOffset   = 0x144
	smOffIPBitmapOffset  = 0x148
	smOffIPBMFreeNextOff = 0x14c

	// bitmapXidOff is where the per-bitmap transaction ids begin inside the
	// spaceman object; the variable-length address arrays follow it.
	bitmapXidOff = 0x150

	sizeofSpacemanDevice    = 48
	sizeofSpacemanFreeQueue = 40
)

// deviceLayout is the computed geometry of one storage device (the main device;
// the tier-2 slot stays empty in the non-Fusion path). "cib" is a chunk-info
// block and "cab" a cib-address block, the two levels of the space manager's
// allocation metadata.
type deviceLayout struct {
	blockCount uint64
	chunkCount uint64
	cibCount   uint32
	cabCount   uint32

	// addrArrayOff is the byte offset, inside the spaceman object, of this
	// device's cib/cab address array.
	addrArrayOff uint32

	firstCib uint64
	firstCab uint64

	usedBlocksEnd uint64 // one past the last allocated block on this device
	usedChunksEnd uint64 // number of chunks that carry any allocation

	firstChunkBmap uint64 // first allocation-bitmap block for this device
}

// spacemanLayout gathers the container-wide space-manager geometry.
type spacemanLayout struct {
	dev [sdCount]deviceLayout

	totalChunkCount uint64
	totalCibCount   uint32
	totalCabCount   uint32

	ipBlocks     uint64 // size of the internal pool, in blocks
	ipBmSize     uint32 // blocks in one internal-pool allocation bitmap
	ipBmapBlocks uint32 // total internal-pool bitmap blocks (the 16-slot ring)
	ipBase       uint64 // first internal-pool block

	bmAddrOff     uint32 // offset of the current-bitmap address array in the object
	bmFreeNextOff uint32 // offset of the bitmap free-list ring in the object
}

func (b *builder) blocksPerChunk() uint64 { return 8 * uint64(b.blocksize) }

func (b *builder) chunksPerCib() uint64 {
	return (uint64(b.blocksize) - sizeofChunkInfoBlockHdr) / sizeofChunkInfo
}

func (b *builder) cibsPerCab() uint64 {
	return (uint64(b.blocksize) - sizeofCibAddrBlockHdr) / 8
}

// spacemanByteSize returns the block-aligned size of the spaceman object. It
// must be large enough to hold the fixed header plus each device's cib (or cab,
// for very large devices) address array; the main device's array is placed last
// so its trailing offset fixes the object's extent.
func (b *builder) spacemanByteSize() uint32 {
	main := &b.sm.dev[sdMain]
	tier2 := &b.sm.dev[sdTier2]

	addrEntries := func(d *deviceLayout) uint64 {
		if d.cabCount > 1 {
			return uint64(d.cabCount)
		}
		return uint64(d.cibCount)
	}
	entryCount := addrEntries(main) + addrEntries(tier2)

	need := entryCount*8 + uint64(main.addrArrayOff)
	return uint32(divRoundUp(need, uint64(b.blocksize)) * uint64(b.blocksize))
}

// rangeOverlap returns how many blocks of [s, e) also lie in [a, c).
func rangeOverlap(s, e, a, c uint64) uint64 {
	lo := max(s, a)
	hi := min(e, c)
	if hi > lo {
		return hi - lo
	}
	return 0
}

// usedInChunk counts the allocated blocks in one chunk of a device. The
// container's allocations form two contiguous spans: the low metadata span —
// block zero, the checkpoint areas, the container object map and every volume's
// trees — and the high span [ipBmapBase, usedBlocksEnd) — the internal-pool
// bitmaps and pool, then the post-pool leaves and file data of every volume. The
// two are separated only by the two skipped Fusion slots. A chunk's used count
// is its overlap with those two spans.
//
// Keeping it to two spans is why the volumes' fixed blocks are laid out
// contiguously: a third span would not fit this model.
func (b *builder) usedInChunk(dev *deviceLayout, chunkno uint64) uint32 {
	if chunkno >= dev.usedChunksEnd {
		return 0
	}
	if dev.usedBlocksEnd == 1 {
		return 1 // an empty tier-2 device carries only a superblock
	}

	start := chunkno * b.blocksPerChunk()
	end := min(start+b.blocksPerChunk(), dev.blockCount)

	lowSpanEnd := b.volFixedBase() + volFixedBlocks*uint64(len(b.vols))
	used := rangeOverlap(start, end, 0, lowSpanEnd)
	used += rangeOverlap(start, end, b.ipBmapBase, dev.usedBlocksEnd)
	return uint32(used)
}

// deviceUsedBlocks totals the allocated blocks across all of a device's chunks.
func (b *builder) deviceUsedBlocks(dev *deviceLayout) uint32 {
	var blocks uint32
	for chunkno := uint64(0); chunkno < dev.usedChunksEnd; chunkno++ {
		blocks += b.usedInChunk(dev, chunkno)
	}
	return blocks
}

// markBits sets length bits starting at bit paddr in an allocation bitmap.
func markBits(bitmap []byte, paddr, length uint64) {
	for i := paddr; i < paddr+length; i++ {
		bitmap[i/8] |= 1 << (i % 8)
	}
}

// writeAllocBitmap writes the main device's allocation bitmap, one bit per
// block, with every block the container occupies marked used.
func (b *builder) writeAllocBitmap() error {
	dev := &b.sm.dev[sdMain]
	bmap := b.zeroedBlocks(int(dev.usedChunksEnd))

	markBits(bmap, 0, 1)                                 // block zero
	markBits(bmap, b.xpDescBase, uint64(b.xpDescBlocks)) // checkpoint descriptor area
	markBits(bmap, b.xpDataBase, uint64(b.xpDataBlocks)) // checkpoint data area
	markBits(bmap, b.mainOmapPaddr, 2)                   // container omap + its root

	// Every volume's fixed blocks, which run contiguously.
	markBits(bmap, b.volFixedBase(), volFixedBlocks*uint64(len(b.vols)))

	markBits(bmap, b.ipBmapBase, uint64(b.sm.ipBmapBlocks)) // internal-pool bitmaps
	markBits(bmap, b.sm.ipBase, b.sm.ipBlocks)              // internal pool
	if b.postIPBlocks > 0 {
		// The volumes' post-pool regions, which are also contiguous: leaves,
		// file data and snapshot objects for each in turn.
		markBits(bmap, b.postIPBase, b.postIPBlocks)
	}

	return b.writeBlocks(bmap, dev.firstChunkBmap)
}

// fillChunkInfo writes one apfs_chunk_info at chunk (a slice into its cib) and
// returns the first block of the following chunk.
func (b *builder) fillChunkInfo(dev *deviceLayout, chunk []byte, start uint64) uint64 {
	chunkno := start / b.blocksPerChunk()
	blockCount := min(b.blocksPerChunk(), dev.blockCount-start)

	binary.LittleEndian.PutUint64(chunk[0:], formatXID) // ci_xid
	binary.LittleEndian.PutUint64(chunk[8:], start)     // ci_addr
	if start < dev.usedBlocksEnd {
		binary.LittleEndian.PutUint64(chunk[24:], dev.firstChunkBmap+chunkno) // ci_bitmap_addr
	}
	binary.LittleEndian.PutUint32(chunk[16:], uint32(blockCount))                             // ci_block_count
	binary.LittleEndian.PutUint32(chunk[20:], uint32(blockCount)-b.usedInChunk(dev, chunkno)) // ci_free_count

	return start + blockCount
}

// writeChunkInfoBlock writes one chunk-info block, filling it with as many
// chunk-info entries as fit or as remain, and returns the next unplaced block.
func (b *builder) writeChunkInfoBlock(dev *deviceLayout, paddr uint64, index int, start uint64) (uint64, error) {
	cib := b.zeroedBlock()
	binary.LittleEndian.PutUint32(cib[32:], uint32(index)) // cib_index

	var placed int
	for placed = 0; uint64(placed) < b.chunksPerCib() && start < dev.blockCount; placed++ {
		chunk := cib[sizeofChunkInfoBlockHdr+placed*sizeofChunkInfo:]
		start = b.fillChunkInfo(dev, chunk, start)
	}
	binary.LittleEndian.PutUint32(cib[36:], uint32(placed)) // cib_chunk_info_count

	setObjectHeader(cib, int(b.blocksize), paddr, objPhysical|objectTypeSpacemanCIB, objectTypeInvalid)
	if err := b.writeBlock(cib, paddr); err != nil {
		return 0, err
	}
	return start, nil
}

// writeDevice fills a device record inside the spaceman object and writes that
// device's chunk-info blocks. The cab (cib-address-block) layer is only reached
// on very large or Fusion devices and is not produced here.
func (b *builder) writeDevice(sm []byte, which int) error {
	d := &b.sm.dev[which]
	rec := sm[smOffDev+which*sizeofSpacemanDevice:]

	binary.LittleEndian.PutUint64(rec[0:], d.blockCount)                                // sm_block_count
	binary.LittleEndian.PutUint64(rec[8:], d.chunkCount)                                // sm_chunk_count
	binary.LittleEndian.PutUint32(rec[16:], d.cibCount)                                 // sm_cib_count
	binary.LittleEndian.PutUint32(rec[20:], d.cabCount)                                 // sm_cab_count
	binary.LittleEndian.PutUint64(rec[24:], d.blockCount-uint64(b.deviceUsedBlocks(d))) // sm_free_count
	binary.LittleEndian.PutUint32(rec[32:], d.addrArrayOff)                             // sm_addr_offset

	if d.cabCount != 0 {
		return errCabUnsupported
	}

	var start uint64
	for i := uint32(0); i < d.cibCount; i++ {
		cibPaddr := d.firstCib + uint64(i)
		binary.LittleEndian.PutUint64(sm[uint64(d.addrArrayOff)+uint64(i)*8:], cibPaddr)
		var err error
		if start, err = b.writeChunkInfoBlock(d, cibPaddr, int(i), start); err != nil {
			return err
		}
	}
	return nil
}

// writeDevices lays out both device slots (the tier-2 slot is empty here).
func (b *builder) writeDevices(sm []byte) error {
	if err := b.writeDevice(sm, sdMain); err != nil {
		return err
	}
	return b.writeDevice(sm, sdTier2)
}

// initIPFreeQueue initializes the internal-pool free queue: an empty ephemeral
// B-tree plus its descriptor (oid and growth cap) inside the spaceman object.
func (b *builder) initIPFreeQueue(fq []byte) error {
	binary.LittleEndian.PutUint64(fq[8:], ipFreeQueueOID) // sfq_tree_oid
	if err := b.writeEmptyTree(b.ipFreeQueuePaddr, ipFreeQueueOID, objectTypeSpacemanFreeQueue); err != nil {
		return err
	}
	binary.LittleEndian.PutUint16(fq[24:], b.ipFreeQueueNodeLimit()) // sfq_tree_node_limit
	return nil
}

// initMainFreeQueue initializes the main-device free queue.
func (b *builder) initMainFreeQueue(fq []byte) error {
	binary.LittleEndian.PutUint64(fq[8:], mainFreeQueueOID)
	if err := b.writeEmptyTree(b.mainFreeQueuePaddr, mainFreeQueueOID, objectTypeSpacemanFreeQueue); err != nil {
		return err
	}
	binary.LittleEndian.PutUint16(fq[24:], b.mainFreeQueueNodeLimit())
	return nil
}

// writeIPBitmap writes the current internal-pool allocation bitmap: it marks the
// pool's own metadata (cab blocks, cib blocks and the device allocation bitmaps)
// as used, since those blocks live inside the pool.
func (b *builder) writeIPBitmap() error {
	bmap := b.zeroedBlocks(int(b.sm.ipBmSize))
	main := &b.sm.dev[sdMain]
	tier2 := &b.sm.dev[sdTier2]
	rel := func(abs uint64) uint64 { return abs - b.sm.ipBase }

	markBits(bmap, rel(main.firstCab), uint64(main.cabCount))
	markBits(bmap, rel(tier2.firstCab), uint64(tier2.cabCount))
	markBits(bmap, rel(main.firstCib), uint64(main.cibCount))
	markBits(bmap, rel(tier2.firstCib), uint64(tier2.cibCount))
	markBits(bmap, rel(main.firstChunkBmap), main.usedChunksEnd)
	markBits(bmap, rel(tier2.firstChunkBmap), tier2.usedChunksEnd)

	return b.writeBlocks(bmap, b.ipBmapBase)
}

// fillBitmapFreeRing writes the free-list ring that links the spare internal-pool
// bitmap slots. The first ipBmSize slots are in use (marked invalid); the rest
// form a singly linked free list terminated by an invalid index.
func (b *builder) fillBitmapFreeRing(ring []byte) {
	put := func(slot uint32, v uint16) { binary.LittleEndian.PutUint16(ring[slot*2:], v) }
	for i := uint32(0); i < b.sm.ipBmSize; i++ {
		put(i, spacemanIPBMIndexInvalid)
	}
	for i := b.sm.ipBmSize; i < b.sm.ipBmapBlocks-1; i++ {
		put(i, uint16(i+1))
	}
	put(b.sm.ipBmapBlocks-1, spacemanIPBMIndexInvalid)
}

// writeInternalPool fills every internal-pool field of the spaceman object and
// writes the pool's bitmap blocks. The pool is a 16-slot ring of allocation
// bitmaps; the first ipBmSize slots hold the live bitmap and the rest are spare.
func (b *builder) writeInternalPool(sm []byte) error {
	binary.LittleEndian.PutUint32(sm[smOffIPBMTxMult:], spacemanIPBMTxMultiplier)
	binary.LittleEndian.PutUint64(sm[smOffIPBlockCount:], b.sm.ipBlocks)
	binary.LittleEndian.PutUint64(sm[smOffIPBase:], b.sm.ipBase)
	binary.LittleEndian.PutUint32(sm[smOffIPBMSizeBlocks:], b.sm.ipBmSize)

	binary.LittleEndian.PutUint32(sm[smOffIPBMBlockCount:], b.sm.ipBmapBlocks)
	binary.LittleEndian.PutUint64(sm[smOffIPBMBase:], b.ipBmapBase)
	zero := b.zeroedBlock()
	for i := uint32(0); i < b.sm.ipBmapBlocks; i++ {
		if err := b.writeBlock(zero, b.ipBmapBase+uint64(i)); err != nil {
			return err
		}
	}

	// The live bitmap occupies the first ipBmSize slots of the ring.
	binary.LittleEndian.PutUint32(sm[smOffIPBitmapOffset:], b.sm.bmAddrOff)
	for i := uint32(0); i < b.sm.ipBmSize; i++ {
		binary.LittleEndian.PutUint16(sm[uint64(b.sm.bmAddrOff)+uint64(i)*2:], uint16(i))
	}
	binary.LittleEndian.PutUint16(sm[smOffIPBMFreeHead:], uint16(b.sm.ipBmSize))
	binary.LittleEndian.PutUint16(sm[smOffIPBMFreeTail:], uint16(b.sm.ipBmapBlocks-1))

	binary.LittleEndian.PutUint32(sm[smOffIPBMXidOffset:], bitmapXidOff)
	for i := uint32(0); i < b.sm.ipBmSize; i++ {
		binary.LittleEndian.PutUint64(sm[bitmapXidOff+uint64(i)*8:], formatXID)
	}

	binary.LittleEndian.PutUint32(sm[smOffIPBMFreeNextOff:], b.sm.bmFreeNextOff)
	b.fillBitmapFreeRing(sm[b.sm.bmFreeNextOff:])

	return b.writeIPBitmap()
}

// deviceGeometry computes a device's chunk/cib/cab counts from its block count.
func (b *builder) deviceGeometry(d *deviceLayout, which int) error {
	if which == sdMain {
		d.blockCount = b.mainBlockCount
	} else {
		d.blockCount = 0 // no tier-2 device
	}
	d.chunkCount = divRoundUp(d.blockCount, b.blocksPerChunk())
	d.cibCount = uint32(divRoundUp(d.chunkCount, b.chunksPerCib()))
	d.cabCount = uint32(divRoundUp(uint64(d.cibCount), b.cibsPerCab()))
	if d.cabCount == 1 {
		d.cabCount = 0 // a single cib needs no cib-address block
	}
	if d.cabCount > 1000 {
		return errDeviceTooBig
	}
	return nil
}

// spacemanGeometry computes all space-manager geometry that does not depend on
// absolute block placement: device counts, internal-pool sizing, and the
// variable-array offsets inside the spaceman object. Because none of this needs
// the checkpoint layout, it can run before block positions are fixed — which is
// what lets the checkpoint data area be sized to the exact spaceman extent.
func (b *builder) spacemanGeometry() error {
	main := &b.sm.dev[sdMain]
	tier2 := &b.sm.dev[sdTier2]
	if err := b.deviceGeometry(main, sdMain); err != nil {
		return err
	}
	if err := b.deviceGeometry(tier2, sdTier2); err != nil {
		return err
	}
	b.sm.totalChunkCount = main.chunkCount + tier2.chunkCount
	b.sm.totalCibCount = main.cibCount + tier2.cibCount
	b.sm.totalCabCount = main.cabCount + tier2.cabCount

	// The internal pool is provisioned at three blocks per allocation-metadata
	// block (chunks + cibs + cabs) so it can hold the bitmaps across transactions.
	b.sm.ipBlocks = (b.sm.totalChunkCount + uint64(b.sm.totalCibCount) + uint64(b.sm.totalCabCount)) * 3
	if b.sm.ipBlocks > b.mainBlockCount/2 {
		return errIPPoolTooBig
	}

	// The bitmap ring has 16 slots; each live bitmap spans ceil(ipBlocks/chunk).
	b.sm.ipBmSize = uint32(divRoundUp(b.sm.ipBlocks, b.blocksPerChunk()))
	b.sm.ipBmapBlocks = 16 * b.sm.ipBmSize

	// Variable arrays follow the per-bitmap xids: the current-bitmap address
	// array, then the free-list ring, then each device's cib/cab address array.
	b.sm.bmAddrOff = bitmapXidOff + 8*b.sm.ipBmSize
	b.sm.bmFreeNextOff = b.sm.bmAddrOff + uint32(roundUp(uint64(2*b.sm.ipBmSize), 8))
	main.addrArrayOff = b.sm.bmFreeNextOff + b.sm.ipBmapBlocks*2
	if main.cabCount != 0 {
		tier2.addrArrayOff = main.addrArrayOff + main.cabCount*8
	} else {
		tier2.addrArrayOff = main.addrArrayOff + main.cibCount*8
	}

	// The spaceman extent is now determined, so the ephemeral-object sizing is
	// too. Record it for the checkpoint layout that follows.
	b.spacemanSz = b.spacemanByteSize()
	b.spacemanBlockCount = b.spacemanSz / b.blocksize
	b.totalBlockCount = b.spacemanBlockCount + 3 // reaper + spaceman + two free-queue roots
	return nil
}

// placePostPool lays out one volume's share of the post-pool region starting at
// base, and returns the first block past it. Each volume's blocks are its own:
// the volume superblock's allocation count names exactly these, so they cannot
// be pooled across volumes.
func (b volCtx) placePostPool(base uint64) uint64 {
	b.fsTreeNodeBase = base
	b.extentrefNodeBase = b.fsTreeNodeBase + b.fsTreeNodes
	b.omapNodeBase = b.extentrefNodeBase + b.extentrefNodes
	b.fileDataBase = b.omapNodeBase + b.omapNodes
	b.placeSnapshots(b.fileDataBase + b.fileDataBlocks)
	b.ownedBlocks = b.fsTreeNodes + b.extentrefNodes + b.omapNodes + b.fileDataBlocks + b.snapBlocks

	blk := b.fileDataBase
	for _, f := range b.streamFiles {
		if f.blocks == 0 {
			continue
		}
		f.dataBlock = blk
		blk += f.blocks
	}
	return base + b.ownedBlocks
}

// spacemanPlacement fixes every absolute block position that depends on the
// checkpoint layout: the ephemeral objects, the internal pool, and the post-pool
// data region (extra file-system tree/extentref leaves and file data). It must run after the
// checkpoint areas and fixed blocks have been laid out.
func (b *builder) spacemanPlacement() error {
	main := &b.sm.dev[sdMain]
	tier2 := &b.sm.dev[sdTier2]

	// Ephemeral objects occupy the checkpoint data area, in order.
	b.reaperPaddr = b.xpDataBase
	b.spacemanPaddr = b.reaperPaddr + 1
	b.ipFreeQueuePaddr = b.spacemanPaddr + uint64(b.spacemanBlockCount)
	b.mainFreeQueuePaddr = b.ipFreeQueuePaddr + 1

	// The internal pool sits just past its bitmap ring.
	b.sm.ipBase = b.ipBmapBase + uint64(b.sm.ipBmapBlocks)

	// Everything the volumes own beyond their fixed metadata is laid out
	// contiguously right after the pool, one volume's region after another.
	// Within a volume: extra file-system tree leaves, then extra
	// extent-reference leaves, then file content, then the snapshot objects
	// (the volume omap's snapshot tree + one snapshot volume superblock per
	// snapshot). The region may span several chunks; the per-chunk accounting
	// handles that.
	b.postIPBase = b.sm.ipBase + b.sm.ipBlocks
	next := b.postIPBase
	for i := range uint64(len(b.vols)) {
		next = b.vol(i).placePostPool(next)
	}
	b.postIPBlocks = next - b.postIPBase
	if next > b.mainBlockCount {
		return errFileDataTooBig
	}

	// The allocated region runs from block zero to the end of the post-pool data.
	main.usedBlocksEnd = b.postIPBase + b.postIPBlocks
	main.usedChunksEnd = divRoundUp(main.usedBlocksEnd, b.blocksPerChunk())
	tier2.usedBlocksEnd = 0
	tier2.usedChunksEnd = 0

	// The allocation bitmaps, then the cibs, then the cabs follow the pool base.
	main.firstChunkBmap = b.sm.ipBase
	main.firstCib = main.firstChunkBmap + main.usedChunksEnd
	main.firstCab = main.firstCib + uint64(main.cibCount)
	tier2.firstChunkBmap = main.firstCab + uint64(main.cabCount)
	tier2.firstCib = tier2.firstChunkBmap + tier2.usedChunksEnd
	tier2.firstCab = tier2.firstCib + uint64(tier2.cibCount)
	return nil
}

// writeSpaceman writes the whole spaceman object: its fixed header, both device
// records with their chunk-info blocks, the two free queues, the internal pool
// and the main allocation bitmap.
func (b *builder) writeSpaceman(paddr, oid uint64) error {
	size := b.spacemanByteSize()
	sm := b.zeroedBlocks(int(size) / int(b.blocksize))

	binary.LittleEndian.PutUint32(sm[smOffBlockSize:], b.blocksize)
	binary.LittleEndian.PutUint32(sm[smOffBlocksPerChunk:], uint32(b.blocksPerChunk()))
	binary.LittleEndian.PutUint32(sm[smOffChunksPerCib:], uint32(b.chunksPerCib()))
	binary.LittleEndian.PutUint32(sm[smOffCibsPerCab:], uint32(b.cibsPerCab()))

	if err := b.writeDevices(sm); err != nil {
		return err
	}
	if err := b.initIPFreeQueue(sm[smOffFQ+sfqIP*sizeofSpacemanFreeQueue:]); err != nil {
		return err
	}
	if err := b.initMainFreeQueue(sm[smOffFQ+sfqMain*sizeofSpacemanFreeQueue:]); err != nil {
		return err
	}
	if err := b.writeInternalPool(sm); err != nil {
		return err
	}
	if err := b.writeAllocBitmap(); err != nil {
		return err
	}

	setObjectHeaderXID(sm, int(size), oid, objEphemeral|objectTypeSpaceman, objectTypeInvalid, b.liveXID)
	return b.writeBlocks(sm, paddr)
}
