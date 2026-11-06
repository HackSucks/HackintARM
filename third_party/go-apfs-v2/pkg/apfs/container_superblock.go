// The APFS container superblock definition
package apfs

import (
	"encoding/binary"
	"fmt"
	"io"
)

// ContainerSuperblock represents the APFS container superblock structure
type ContainerSuperblock struct {
	// The object checksum
	// Consists of 8 bytes
	Checksum uint64

	// The object identifier
	// Consists of 8 bytes
	OID uint64

	// The object transaction identifier
	// Consists of 8 bytes
	XID uint64

	// The object type
	// Consists of 4 bytes
	ObjectType uint32

	// The object subtype
	// Consists of 4 bytes
	ObjectSubtype uint32

	// The file system signature
	// Consists of 4 bytes
	// Contains: "NXSB"
	Signature [4]byte

	// The block size
	// Consists of 4 bytes
	BlockSize uint32

	// The number of blocks
	// Consists of 8 bytes
	NumberOfBlocks uint64

	// Compatible features flags
	// Consists of 8 bytes
	CompatibleFeaturesFlags uint64

	// Read only compatible features flags
	// Consists of 8 bytes
	ReadOnlyCompatibleFeaturesFlags uint64

	// Incompatible features flags
	// Consists of 8 bytes
	IncompatibleFeaturesFlags uint64

	// The container identifier
	// Consists of 16 bytes
	// Contains an UUID
	UUID [16]byte

	// The next object identifier
	// Consists of 8 bytes
	NextOID uint64

	// The next transaction identifier
	// Consists of 8 bytes
	NextXID uint64

	// The checkpoint descriptor area number of blocks
	// Consists of 4 bytes
	XPDescBlocks uint32

	// The checkpoint data area number of blocks
	// Consists of 4 bytes
	XPDataBlocks uint32

	// The checkpoint descriptor area block number
	// Consists of 8 bytes
	XPDescBase uint64

	// The checkpoint data area block number
	// Consists of 8 bytes
	XPDataBase uint64

	// The next index in the checkpoint descriptor area to write to (nx_xp_desc_next)
	// Consists of 4 bytes
	XPDescNext uint32

	// The next index in the checkpoint data area to write to (nx_xp_data_next)
	// Consists of 4 bytes
	XPDataNext uint32

	// The index of the first valid item in the checkpoint descriptor area (nx_xp_desc_index)
	// Consists of 4 bytes
	XPDescIndex uint32

	// The number of blocks in the checkpoint descriptor area used by the checkpoint (nx_xp_desc_len)
	// Consists of 4 bytes
	XPDescLen uint32

	// The index of the first valid item in the checkpoint data area (nx_xp_data_index)
	// Consists of 4 bytes
	XPDataIndex uint32

	// The number of blocks in the checkpoint data area used by the checkpoint (nx_xp_data_len)
	// Consists of 4 bytes
	XPDataLen uint32

	// The space manager object identifier
	// Consists of 8 bytes
	SpacemanOID uint64

	// The object map block number
	// Consists of 8 bytes
	OmapOID uint64

	// The reaper object identifier
	// Consists of 8 bytes
	ReaperOID uint64

	// Reserved for testing; treated as zero on production volumes (nx_test_type)
	// Consists of 4 bytes
	TestType uint32

	// The maximum number of volumes
	// Consists of 4 bytes
	MaxVolumes uint32

	// The volume object identifiers
	// Consists of 100 x 8 bytes
	VolumeOIDs [800]byte

	// The counters
	// Consists of 32 x 8 bytes
	Counters [256]byte

	// The first block of the blocked-out range (nx_blocked_out_prange.pr_start_paddr)
	// Consists of 8 bytes
	BlockedOutStartPaddr uint64

	// The number of blocks in the blocked-out range (nx_blocked_out_prange.pr_block_count)
	// Consists of 8 bytes
	BlockedOutBlockCount uint64

	// The object identifier of the tree used to keep track of evicted objects (nx_evict_mapping_tree_oid)
	// Consists of 8 bytes
	EvictMappingTreeOID uint64

	// The container flags (nx_flags)
	// Consists of 8 bytes
	Flags uint64

	// The physical address of the embedded EFI driver (nx_efi_jumpstart)
	// Consists of 8 bytes
	EFIJumpstart uint64

	// The Fusion set identifier
	// Consists of 16 bytes
	// Contains an UUID
	FusionUUID [16]byte

	// The keybag block number
	// Consists of 8 bytes
	KeylockerStartPaddr uint64

	// The keybag number of blocks
	// Consists of 8 bytes
	KeylockerBlockCount uint64

	// Ephemeral object information (nx_ephemeral_info[NX_EPH_INFO_COUNT])
	// Consists of 4 x 8 bytes
	EphemeralInfo [32]byte

	// Reserved for testing (nx_test_oid)
	// Consists of 8 bytes
	TestOID uint64

	// The Fusion middle tree block number
	// Consists of 8 bytes
	FusionMtOID uint64

	// The Fusion write-back cache object identifier
	// Consists of 8 bytes
	FusionWbcOID uint64

	// The first block of the Fusion write-back cache range (nx_fusion_wbc.pr_start_paddr)
	// Consists of 8 bytes
	FusionWbcStartPaddr uint64

	// The number of blocks in the Fusion write-back cache range (nx_fusion_wbc.pr_block_count)
	// Consists of 8 bytes
	FusionWbcBlockCount uint64
}

// Container superblock constants
const (
	ContainerSuperblockObjectType = 0x80000001
	ContainerSuperblockSignature  = "NXSB"
	ContainerSuperblockSize       = 4096
)

// NewContainerSuperblock creates a new container superblock
func NewContainerSuperblock() (*ContainerSuperblock, error) {
	return &ContainerSuperblock{}, nil
}

// ReadFrom reads the container superblock from a file
func (csb *ContainerSuperblock) ReadFrom(
	reader io.ReaderAt,
	fileOffset int64,
) error {
	if csb == nil {
		return fmt.Errorf("invalid container superblock")
	}

	// Container superblock is always 4096 bytes
	data := make([]byte, ContainerSuperblockSize)
	n, err := reader.ReadAt(data, fileOffset)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read container superblock data at offset %d: %w", fileOffset, err)
	}
	if n != ContainerSuperblockSize {
		return fmt.Errorf("unable to read complete container superblock data: expected %d bytes, got %d", ContainerSuperblockSize, n)
	}

	return csb.ReadData(data)
}

// ReadData reads the container superblock from data
func (csb *ContainerSuperblock) ReadData(data []byte) error {
	if csb == nil {
		return fmt.Errorf("invalid container superblock")
	}

	if data == nil {
		return fmt.Errorf("invalid data")
	}

	if len(data) < ContainerSuperblockSize {
		return fmt.Errorf("invalid data size: expected at least %d bytes, got %d", ContainerSuperblockSize, len(data))
	}

	// Read and validate checksum
	storedChecksum := binary.LittleEndian.Uint64(data[0:8])
	calculatedChecksum, err := CalculateFletcher64(data[8:], 0)
	if err != nil {
		return fmt.Errorf("unable to calculate Fletcher 64 checksum: %w", err)
	}
	if storedChecksum != calculatedChecksum {
		return fmt.Errorf("checksum mismatch (0x%016x != 0x%016x)", storedChecksum, calculatedChecksum)
	}

	// Parse object header
	csb.Checksum = storedChecksum
	csb.OID = binary.LittleEndian.Uint64(data[8:16])
	csb.XID = binary.LittleEndian.Uint64(data[16:24])
	csb.ObjectType = binary.LittleEndian.Uint32(data[24:28])
	csb.ObjectSubtype = binary.LittleEndian.Uint32(data[28:32])

	// Validate object type
	if csb.ObjectType != ContainerSuperblockObjectType {
		return fmt.Errorf("invalid object type: 0x%08x (expected 0x%08x)", csb.ObjectType, ContainerSuperblockObjectType)
	}

	// Validate object subtype
	if csb.ObjectSubtype != 0x00000000 {
		return fmt.Errorf("invalid object subtype: 0x%08x", csb.ObjectSubtype)
	}

	// Read signature
	copy(csb.Signature[:], data[32:36])
	if string(csb.Signature[:]) != ContainerSuperblockSignature {
		return fmt.Errorf("invalid signature: %s (expected %s)", string(csb.Signature[:]), ContainerSuperblockSignature)
	}

	// Read superblock fields
	csb.BlockSize = binary.LittleEndian.Uint32(data[36:40])
	csb.NumberOfBlocks = binary.LittleEndian.Uint64(data[40:48])
	csb.CompatibleFeaturesFlags = binary.LittleEndian.Uint64(data[48:56])
	csb.ReadOnlyCompatibleFeaturesFlags = binary.LittleEndian.Uint64(data[56:64])
	csb.IncompatibleFeaturesFlags = binary.LittleEndian.Uint64(data[64:72])

	// Debug output for container feature flags
	if DebugOutput {
		fmt.Printf("Container compatible features flags: 0x%016x\n", csb.CompatibleFeaturesFlags)
		PrintContainerCompatibleFeaturesFlags(csb.CompatibleFeaturesFlags)
		fmt.Printf("Container read-only compatible features flags: 0x%016x\n", csb.ReadOnlyCompatibleFeaturesFlags)
		PrintContainerReadOnlyCompatibleFeaturesFlags(csb.ReadOnlyCompatibleFeaturesFlags)
		fmt.Printf("Container incompatible features flags: 0x%016x\n", csb.IncompatibleFeaturesFlags)
		PrintContainerIncompatibleFeaturesFlags(csb.IncompatibleFeaturesFlags)
	}

	copy(csb.UUID[:], data[72:88])

	// Debug output for container identifier GUID
	if DebugOutput {
		if err := PrintGUIDValue("ContainerSuperblock.ReadData", "container identifier", csb.UUID[:], binary.LittleEndian); err != nil {
			fmt.Printf("Warning: unable to print container identifier GUID: %v\n", err)
		}
	}

	csb.NextOID = binary.LittleEndian.Uint64(data[88:96])
	csb.NextXID = binary.LittleEndian.Uint64(data[96:104])
	csb.XPDescBlocks = binary.LittleEndian.Uint32(data[104:108])
	csb.XPDataBlocks = binary.LittleEndian.Uint32(data[108:112])
	csb.XPDescBase = binary.LittleEndian.Uint64(data[112:120])
	csb.XPDataBase = binary.LittleEndian.Uint64(data[120:128])
	csb.XPDescNext = binary.LittleEndian.Uint32(data[128:132])
	csb.XPDataNext = binary.LittleEndian.Uint32(data[132:136])
	csb.XPDescIndex = binary.LittleEndian.Uint32(data[136:140])
	csb.XPDescLen = binary.LittleEndian.Uint32(data[140:144])
	csb.XPDataIndex = binary.LittleEndian.Uint32(data[144:148])
	csb.XPDataLen = binary.LittleEndian.Uint32(data[148:152])
	csb.SpacemanOID = binary.LittleEndian.Uint64(data[152:160])
	csb.OmapOID = binary.LittleEndian.Uint64(data[160:168])
	csb.ReaperOID = binary.LittleEndian.Uint64(data[168:176])
	csb.TestType = binary.LittleEndian.Uint32(data[176:180])
	csb.MaxVolumes = binary.LittleEndian.Uint32(data[180:184])

	// Read volume object identifiers (100 x 8 bytes = 800 bytes at offset 184)
	copy(csb.VolumeOIDs[:], data[184:984])

	// Read counters (32 x 8 bytes = 256 bytes at offset 984)
	copy(csb.Counters[:], data[984:1240])

	// Read remaining fields
	csb.BlockedOutStartPaddr = binary.LittleEndian.Uint64(data[1240:1248])
	csb.BlockedOutBlockCount = binary.LittleEndian.Uint64(data[1248:1256])
	csb.EvictMappingTreeOID = binary.LittleEndian.Uint64(data[1256:1264])
	csb.Flags = binary.LittleEndian.Uint64(data[1264:1272])
	csb.EFIJumpstart = binary.LittleEndian.Uint64(data[1272:1280])
	copy(csb.FusionUUID[:], data[1280:1296])

	// Debug output for Fusion set identifier GUID
	if DebugOutput {
		if err := PrintGUIDValue("ContainerSuperblock.ReadData", "Fusion set identifier", csb.FusionUUID[:], binary.BigEndian); err != nil {
			fmt.Printf("Warning: unable to print Fusion set identifier GUID: %v\n", err)
		}
	}

	csb.KeylockerStartPaddr = binary.LittleEndian.Uint64(data[1296:1304])
	csb.KeylockerBlockCount = binary.LittleEndian.Uint64(data[1304:1312])
	copy(csb.EphemeralInfo[:], data[1312:1344])
	csb.TestOID = binary.LittleEndian.Uint64(data[1344:1352])
	csb.FusionMtOID = binary.LittleEndian.Uint64(data[1352:1360])
	csb.FusionWbcOID = binary.LittleEndian.Uint64(data[1360:1368])
	csb.FusionWbcStartPaddr = binary.LittleEndian.Uint64(data[1368:1376])
	csb.FusionWbcBlockCount = binary.LittleEndian.Uint64(data[1376:1384])

	// Validate incompatible features
	if (csb.IncompatibleFeaturesFlags & 0x0000000000000001) != 0 {
		return fmt.Errorf("unsupported format version 1")
	}

	// Validate block size
	// This reader handles one block size. Note the check is not what actually
	// rejects a larger container: ReadFrom reads a fixed ContainerSuperblockSize
	// bytes and the checksum above covers exactly that span, whereas the object's
	// checksum is sealed over the whole block -- so an 8 KiB container fails as a
	// checksum mismatch before reaching here. Supporting other sizes therefore
	// means a two-phase superblock read (peek nx_block_size, re-read the full
	// block, then verify), not deleting this check. pkg/apfswrite refuses to
	// write anything but 4096 for the same reason.
	if csb.BlockSize != 4096 {
		return fmt.Errorf("unsupported block size: %d (expected 4096)", csb.BlockSize)
	}

	// Validate checkpoint descriptor area
	if (csb.XPDescBlocks & 0x80000000) != 0 {
		return fmt.Errorf("unsupported checkpoint descriptor area number of blocks - MSB is set")
	}

	if csb.XPDescBase == 0 {
		return fmt.Errorf("invalid checkpoint descriptor area block number: 0")
	}

	// Validate maximum number of volumes
	if csb.MaxVolumes > 100 {
		return fmt.Errorf("invalid maximum number of volumes: %d (max 100)", csb.MaxVolumes)
	}

	return nil
}

// ContainerIdentifier retrieves the container identifier (UUID)
func (csb *ContainerSuperblock) ContainerIdentifier() ([]byte, error) {
	if csb == nil {
		return nil, fmt.Errorf("invalid container superblock")
	}

	// Return a copy of the container identifier
	identifier := make([]byte, 16)
	copy(identifier, csb.UUID[:])
	return identifier, nil
}

// VolumeObjectIdentifiers returns the array of volume object identifiers
// Returns a slice of uint64 values (non-zero entries only)
func (csb *ContainerSuperblock) VolumeObjectIdentifiers() ([]uint64, error) {
	if csb == nil {
		return nil, fmt.Errorf("invalid container superblock")
	}

	volumeIDs := make([]uint64, 0, 100)

	// Parse the 800-byte array as 100 uint64 values
	for i := 0; i < 100; i++ {
		offset := i * 8
		volumeID := binary.LittleEndian.Uint64(csb.VolumeOIDs[offset : offset+8])
		if volumeID != 0 {
			volumeIDs = append(volumeIDs, volumeID)
		}
	}

	return volumeIDs, nil
}
