package apfs

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Space manager constants (Apple: SD_COUNT, SFQ_COUNT).
const (
	// SpaceManagerDeviceCount is the number of storage devices a space manager
	// describes: the main device and, on Fusion drives, the Tier2 device.
	SpaceManagerDeviceCount = 2
	// SpaceManagerFreeQueueCount is the number of free queues.
	SpaceManagerFreeQueueCount = 3

	// Device indexes (Apple: enum smdev).
	SpaceManagerDeviceMain  = 0 // SD_MAIN
	SpaceManagerDeviceTier2 = 1 // SD_TIER2

	// Free queue indexes (Apple: enum sfq).
	SpaceManagerFreeQueueIP    = 0 // SFQ_IP, the internal pool
	SpaceManagerFreeQueueMain  = 1 // SFQ_MAIN
	SpaceManagerFreeQueueTier2 = 2 // SFQ_TIER2

	// SpaceManagerDeviceSize is the on-disk size of spaceman_device_t.
	SpaceManagerDeviceSize = 48
	// SpaceManagerFreeQueueSize is the on-disk size of spaceman_free_queue_t.
	SpaceManagerFreeQueueSize = 40
	// SpaceManagerAllocationZoneSize is the on-disk size of one device's
	// allocation-zone array within sm_datazone.
	SpaceManagerAllocationZoneSize = 576

	// SpaceManagerObjectType is the object type of a space manager
	// (OBJECT_TYPE_SPACEMAN with OBJ_EPHEMERAL set).
	SpaceManagerObjectType = 0x80000005
)

// SpaceManagerDevice describes one storage device managed by the space
// manager (Apple: spaceman_device_t).
type SpaceManagerDevice struct {
	BlockCount uint64 // sm_block_count
	ChunkCount uint64 // sm_chunk_count
	CIBCount   uint32 // sm_cib_count
	CABCount   uint32 // sm_cab_count
	FreeCount  uint64 // sm_free_count
	AddrOffset uint32 // sm_addr_offset
	Reserved   uint32 // sm_reserved
	Reserved2  uint64 // sm_reserved2
}

// SpaceManagerFreeQueue is a queue of blocks that become free once the
// transactions still referring to them are no longer needed (Apple:
// spaceman_free_queue_t).
type SpaceManagerFreeQueue struct {
	Count         uint64 // sfq_count
	TreeOID       uint64 // sfq_tree_oid
	OldestXID     uint64 // sfq_oldest_xid
	TreeNodeLimit uint16 // sfq_tree_node_limit
	Pad16         uint16 // sfq_pad16
	Pad32         uint32 // sfq_pad32
	Reserved      uint64 // sfq_reserved
}

// SpaceManager allocates and frees the blocks where objects and file data are
// stored. There is exactly one of these in a container (Apple:
// spaceman_phys_t).
type SpaceManager struct {
	// Object header (obj_phys_t).
	Checksum      uint64 // o_cksum
	OID           uint64 // o_oid
	XID           uint64 // o_xid
	ObjectType    uint32 // o_type
	ObjectSubtype uint32 // o_subtype

	BlockSize      uint32 // sm_block_size
	BlocksPerChunk uint32 // sm_blocks_per_chunk
	ChunksPerCIB   uint32 // sm_chunks_per_cib
	CIBsPerCAB     uint32 // sm_cibs_per_cab

	// Devices, indexed by SpaceManagerDeviceMain/Tier2 (sm_dev).
	Devices [SpaceManagerDeviceCount]SpaceManagerDevice

	Flags uint32 // sm_flags

	// Internal pool. Apple's field prefix is sm_ip_; the spec section is
	// titled "Internal-Pool Bitmap".
	IPBMTxMultiplier   uint32 // sm_ip_bm_tx_multiplier
	IPBlockCount       uint64 // sm_ip_block_count
	IPBMSizeInBlocks   uint32 // sm_ip_bm_size_in_blocks
	IPBMBlockCount     uint32 // sm_ip_bm_block_count
	IPBMBase           uint64 // sm_ip_bm_base (paddr_t)
	IPBase             uint64 // sm_ip_base (paddr_t)
	IPBMFreeHead       uint16 // sm_ip_bm_free_head
	IPBMFreeTail       uint16 // sm_ip_bm_free_tail
	IPBMXIDOffset      uint32 // sm_ip_bm_xid_offset
	IPBitmapOffset     uint32 // sm_ip_bitmap_offset
	IPBMFreeNextOffset uint32 // sm_ip_bm_free_next_offset

	FSReserveBlockCount uint64 // sm_fs_reserve_block_count
	FSReserveAllocCount uint64 // sm_fs_reserve_alloc_count

	// Free queues, indexed by SpaceManagerFreeQueueIP/Main/Tier2 (sm_fq).
	FreeQueues [SpaceManagerFreeQueueCount]SpaceManagerFreeQueue

	Version    uint32 // sm_version
	StructSize uint32 // sm_struct_size

	// Allocation-zone information for each device, undecoded (sm_datazone,
	// spaceman_datazone_info_phys_t).
	DataZone [SpaceManagerDeviceCount][SpaceManagerAllocationZoneSize]byte
}

// NewSpaceManager creates a new space manager
func NewSpaceManager() *SpaceManager {
	return &SpaceManager{}
}

// ReadFrom reads the space manager from a reader at the specified offset
func (sm *SpaceManager) ReadFrom(reader io.ReaderAt, fileOffset int64) error {
	if sm == nil {
		return fmt.Errorf("invalid space manager")
	}

	if DebugOutput {
		fmt.Printf("Reading space manager at offset: %d (0x%08x)\n", fileOffset, fileOffset)
	}

	// Read 4096 bytes (size of space manager)
	data := make([]byte, 4096)
	n, err := reader.ReadAt(data, fileOffset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read space manager data at offset %d (0x%08x): %w",
			fileOffset, fileOffset, err)
	}
	if n != 4096 {
		return fmt.Errorf("unable to read space manager data at offset %d (0x%08x): read %d bytes, expected 4096",
			fileOffset, fileOffset, n)
	}

	// Parse the data
	if err := sm.ReadData(data); err != nil {
		return fmt.Errorf("unable to read space manager data: %w", err)
	}

	return nil
}

// ReadData reads the space manager from binary data
func (sm *SpaceManager) ReadData(data []byte) error {
	if sm == nil {
		return fmt.Errorf("invalid space manager")
	}
	if data == nil {
		return fmt.Errorf("invalid data")
	}
	if len(data) < 200 {
		return fmt.Errorf("invalid data size: %d bytes (minimum 200)", len(data))
	}

	// Object header (obj_phys_t), offsets 0..32
	sm.Checksum = binary.LittleEndian.Uint64(data[0:8])
	sm.OID = binary.LittleEndian.Uint64(data[8:16])
	sm.XID = binary.LittleEndian.Uint64(data[16:24])
	sm.ObjectType = binary.LittleEndian.Uint32(data[24:28])
	sm.ObjectSubtype = binary.LittleEndian.Uint32(data[28:32])

	if sm.ObjectType != SpaceManagerObjectType {
		return fmt.Errorf("invalid object type: 0x%08x (expected 0x%08x)", sm.ObjectType, SpaceManagerObjectType)
	}
	if sm.ObjectSubtype != 0x00000000 {
		return fmt.Errorf("invalid object subtype: 0x%08x (expected 0x00000000)", sm.ObjectSubtype)
	}

	sm.BlockSize = binary.LittleEndian.Uint32(data[32:36])
	sm.BlocksPerChunk = binary.LittleEndian.Uint32(data[36:40])
	sm.ChunksPerCIB = binary.LittleEndian.Uint32(data[40:44])
	sm.CIBsPerCAB = binary.LittleEndian.Uint32(data[44:48])

	// sm_dev[SD_COUNT], offsets 48..144
	for i := range sm.Devices {
		d := data[48+i*SpaceManagerDeviceSize:]
		sm.Devices[i] = SpaceManagerDevice{
			BlockCount: binary.LittleEndian.Uint64(d[0:8]),
			ChunkCount: binary.LittleEndian.Uint64(d[8:16]),
			CIBCount:   binary.LittleEndian.Uint32(d[16:20]),
			CABCount:   binary.LittleEndian.Uint32(d[20:24]),
			FreeCount:  binary.LittleEndian.Uint64(d[24:32]),
			AddrOffset: binary.LittleEndian.Uint32(d[32:36]),
			Reserved:   binary.LittleEndian.Uint32(d[36:40]),
			Reserved2:  binary.LittleEndian.Uint64(d[40:48]),
		}
	}

	// Flags, internal pool and file-system reserve, offsets 144..200
	sm.Flags = binary.LittleEndian.Uint32(data[144:148])
	sm.IPBMTxMultiplier = binary.LittleEndian.Uint32(data[148:152])
	sm.IPBlockCount = binary.LittleEndian.Uint64(data[152:160])
	sm.IPBMSizeInBlocks = binary.LittleEndian.Uint32(data[160:164])
	sm.IPBMBlockCount = binary.LittleEndian.Uint32(data[164:168])
	sm.IPBMBase = binary.LittleEndian.Uint64(data[168:176])
	sm.IPBase = binary.LittleEndian.Uint64(data[176:184])
	sm.FSReserveBlockCount = binary.LittleEndian.Uint64(data[184:192])
	sm.FSReserveAllocCount = binary.LittleEndian.Uint64(data[192:200])

	// Everything past the reserve counts needs the full structure.
	if len(data) < 1496 {
		return nil
	}

	// sm_fq[SFQ_COUNT], offsets 200..320
	for i := range sm.FreeQueues {
		q := data[200+i*SpaceManagerFreeQueueSize:]
		sm.FreeQueues[i] = SpaceManagerFreeQueue{
			Count:         binary.LittleEndian.Uint64(q[0:8]),
			TreeOID:       binary.LittleEndian.Uint64(q[8:16]),
			OldestXID:     binary.LittleEndian.Uint64(q[16:24]),
			TreeNodeLimit: binary.LittleEndian.Uint16(q[24:26]),
			Pad16:         binary.LittleEndian.Uint16(q[26:28]),
			Pad32:         binary.LittleEndian.Uint32(q[28:32]),
			Reserved:      binary.LittleEndian.Uint64(q[32:40]),
		}
	}

	// Internal-pool bitmap ring and version, offsets 320..344
	sm.IPBMFreeHead = binary.LittleEndian.Uint16(data[320:322])
	sm.IPBMFreeTail = binary.LittleEndian.Uint16(data[322:324])
	sm.IPBMXIDOffset = binary.LittleEndian.Uint32(data[324:328])
	sm.IPBitmapOffset = binary.LittleEndian.Uint32(data[328:332])
	sm.IPBMFreeNextOffset = binary.LittleEndian.Uint32(data[332:336])
	sm.Version = binary.LittleEndian.Uint32(data[336:340])
	sm.StructSize = binary.LittleEndian.Uint32(data[340:344])

	// sm_datazone, offsets 344..1496: one allocation-zone array per device.
	for i := range sm.DataZone {
		start := 344 + i*SpaceManagerAllocationZoneSize
		copy(sm.DataZone[i][:], data[start:start+SpaceManagerAllocationZoneSize])
	}

	// Note: sm_dev[].sm_addr_offset points at further per-device structures
	// (the chunk-info block and CIB address block arrays). Reading those is
	// not implemented; see ChunkInfoBlock for the block-level structure.

	return nil
}
