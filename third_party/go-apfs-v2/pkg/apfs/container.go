// The APFS container definition
package apfs

import (
	"fmt"
	"io"
	"math"
)

// Container represents an APFS container
type Container struct {
	// The container superblock
	Superblock *ContainerSuperblock

	// The Fusion middle tree (optional, used in Fusion drives)
	FusionMiddleTree *FusionMiddleTree

	// The checkpoint map
	CheckpointMap *CheckpointMap

	// The container data handle
	ContainerDataHandle *ContainerDataHandle

	// The object map B-tree
	ObjectMapBTree *ObjectMapBTree

	// The container keybag (optional, used for encryption)
	Keybag *ContainerKeybag

	// The space manager (optional, tracks block allocation)
	SpaceManager *SpaceManager

	// The IO handle
	IOHandle *IOHandle

	// The file IO handle
	Reader io.ReaderAt

	// Passwords supplied via OpenOptions, applied to volumes on access
	userPassword     string
	recoveryPassword string
}

// NewContainer creates a new container
func NewContainer(ioHandle *IOHandle) (*Container, error) {
	if ioHandle == nil {
		return nil, fmt.Errorf("invalid IO handle")
	}

	return &Container{
		IOHandle: ioHandle,
	}, nil
}

// Close releases resources associated with the container
func (c *Container) Close() error {
	if c == nil {
		return fmt.Errorf("invalid container")
	}

	// Free keybag
	if c.Keybag != nil {
		if err := c.Keybag.Close(); err != nil {
			return fmt.Errorf("unable to free keybag: %w", err)
		}
		c.Keybag = nil
	}

	// Free space manager
	if c.SpaceManager != nil {
		c.SpaceManager = nil
	}

	// Free object map B-tree
	c.ObjectMapBTree = nil

	// Free container data handle
	if c.ContainerDataHandle != nil {
		c.ContainerDataHandle = nil
	}

	// Free checkpoint map
	c.CheckpointMap = nil

	// Free fusion middle tree
	c.FusionMiddleTree = nil

	// Free superblock
	if c.Superblock != nil {
		c.Superblock = nil
	}

	return nil
}

// OpenRead opens a container for reading
func (c *Container) OpenRead(reader io.ReaderAt, fileOffset int64) error {
	if c == nil {
		return fmt.Errorf("invalid container")
	}

	if c.IOHandle == nil {
		return fmt.Errorf("invalid container - missing IO handle")
	}

	if c.Superblock != nil {
		return fmt.Errorf("invalid container - superblock already set")
	}

	if c.FusionMiddleTree != nil {
		return fmt.Errorf("invalid container - Fusion middle tree already set")
	}

	if c.CheckpointMap != nil {
		return fmt.Errorf("invalid container - checkpoint map already set")
	}

	if c.ObjectMapBTree != nil {
		return fmt.Errorf("invalid container - object map B-tree already set")
	}

	if c.Keybag != nil {
		return fmt.Errorf("invalid container - keybag already set")
	}

	if c.SpaceManager != nil {
		return fmt.Errorf("invalid container - space manager already set")
	}

	// All block-number arithmetic in the container, volumes, B-trees and data
	// streams is relative to the start of the APFS partition. When the caller
	// hands us a handle where the container starts at a non-zero offset (e.g. a
	// GPT-partitioned raw image), rebase the handle once here so every
	// downstream ReadAt computes partition-relative offsets against offset 0.
	if fileOffset != 0 {
		reader = io.NewSectionReader(reader, fileOffset, math.MaxInt64-fileOffset)
		fileOffset = 0
	}

	// Store the file handle for later use
	c.Reader = reader

	// Read the container superblock at the given offset
	superblock, err := NewContainerSuperblock()
	if err != nil {
		return fmt.Errorf("unable to create container superblock: %w", err)
	}

	if err := superblock.ReadFrom(reader, fileOffset); err != nil {
		return fmt.Errorf("unable to read container superblock at offset %d: %w", fileOffset, err)
	}

	c.Superblock = superblock

	// Update IO handle with block size and container size from superblock
	c.IOHandle.BlockSize = superblock.BlockSize
	c.IOHandle.ContainerSize = superblock.NumberOfBlocks * uint64(superblock.BlockSize)

	// Check for unsupported Fusion drive feature (only in non-debug mode)
	if (superblock.IncompatibleFeaturesFlags & 0x0000000000000100) != 0 {
		return fmt.Errorf("Fusion drive not supported")
	}

	// Read Fusion middle tree if present (for debug output)
	if DebugOutput && superblock.FusionMtOID != 0 {
		fusionMiddleTree, err := NewFusionMiddleTree()
		if err != nil {
			return fmt.Errorf("unable to create Fusion middle tree: %w", err)
		}

		fusionMiddleTreeOffset := int64(superblock.FusionMtOID) * int64(c.IOHandle.BlockSize)

		if err := fusionMiddleTree.ReadFrom(reader, fusionMiddleTreeOffset); err != nil {
			return fmt.Errorf("unable to read Fusion middle tree at offset %d: %w", fusionMiddleTreeOffset, err)
		}

		c.FusionMiddleTree = fusionMiddleTree
	}

	// Scan checkpoint descriptor area to find the latest checkpoint map and superblock
	checkpointMapBlockNumber := uint64(0)
	checkpointMapTransactionIdentifier := uint64(0)

	object, err := NewObjectHeader()
	if err != nil {
		return fmt.Errorf("unable to create object: %w", err)
	}

	scanOffset := int64(superblock.XPDescBase) * int64(c.IOHandle.BlockSize)

	// NOTE: Using < not <= based on drat implementation (libfsapfs uses <= which appears to be a bug)
	for metadataBlockIndex := uint32(0); metadataBlockIndex < superblock.XPDescBlocks; metadataBlockIndex++ {
		if err := object.ReadFrom(reader, scanOffset); err != nil {
			return fmt.Errorf("unable to read object at offset %d: %w", scanOffset, err)
		}

		switch object.Type {
		case 0x4000000c: // Checkpoint map object type
			// Track the checkpoint map with the highest transaction identifier
			if object.XID > checkpointMapTransactionIdentifier {
				checkpointMapBlockNumber = superblock.XPDescBase + uint64(metadataBlockIndex)
				checkpointMapTransactionIdentifier = object.XID
			}

		case 0x80000001: // Container superblock object type
			// Read backup container superblock
			backupSuperblock, err := NewContainerSuperblock()
			if err != nil {
				return fmt.Errorf("unable to create backup container superblock: %w", err)
			}

			if err := backupSuperblock.ReadFrom(reader, scanOffset); err != nil {
				return fmt.Errorf("unable to read backup container superblock at offset %d: %w", scanOffset, err)
			}

			// Use the superblock with the highest transaction identifier
			if backupSuperblock.XID > c.Superblock.XID {
				c.Superblock = backupSuperblock
			}
		}

		scanOffset += int64(c.IOHandle.BlockSize)
	}

	if checkpointMapBlockNumber == 0 {
		return fmt.Errorf("missing checkpoint map block number")
	}

	// Read the checkpoint map
	checkpointMap := NewCheckpointMap()
	checkpointMapOffset := int64(checkpointMapBlockNumber) * int64(c.IOHandle.BlockSize)

	if err := checkpointMap.ReadFrom(reader, checkpointMapOffset); err != nil {
		return fmt.Errorf("unable to read checkpoint map at offset %d: %w", checkpointMapOffset, err)
	}

	c.CheckpointMap = checkpointMap

	// Create container data handle
	containerDataHandle, err := NewContainerDataHandle(c.IOHandle)
	if err != nil {
		return fmt.Errorf("unable to create container data handle: %w", err)
	}

	c.ContainerDataHandle = containerDataHandle

	// Read object map
	if c.Superblock.OmapOID == 0 {
		return fmt.Errorf("missing object map block number")
	}

	objectMapOffset := int64(c.Superblock.OmapOID) * int64(c.IOHandle.BlockSize)

	objectMap, err := NewObjectMap()
	if err != nil {
		return fmt.Errorf("unable to create object map: %w", err)
	}

	if err := objectMap.ReadFrom(reader, objectMapOffset); err != nil {
		return fmt.Errorf("unable to read object map at offset %d: %w", objectMapOffset, err)
	}

	if objectMap.TreeOID == 0 {
		return fmt.Errorf("missing object map B-tree block number")
	}

	// Create object map B-tree
	// Note: Container-level B-tree is not encrypted
	objectMapBTree, err := NewObjectMapBTree(
		c.IOHandle,
		nil, // No encryption context for container-level objects
		objectMap.TreeOID,
	)
	if err != nil {
		return fmt.Errorf("unable to create object map B-tree: %w", err)
	}
	c.ObjectMapBTree = objectMapBTree

	// Free the object map as we only needed it to get the B-tree block number

	// Read container keybag if present
	if c.Superblock.KeylockerStartPaddr > 0 && c.Superblock.KeylockerBlockCount > 0 {
		keybag, err := NewContainerKeybag()
		if err != nil {
			return fmt.Errorf("unable to create container keybag: %w", err)
		}

		keybagOffset := int64(c.Superblock.KeylockerStartPaddr) * int64(c.IOHandle.BlockSize)
		keybagSize := c.Superblock.KeylockerBlockCount * uint64(c.IOHandle.BlockSize)

		containerIdentifier, err := c.Superblock.ContainerIdentifier()
		if err != nil {
			keybag.Close()
			return fmt.Errorf("unable to get container identifier: %w", err)
		}

		err = keybag.ReadFrom(
			c.IOHandle,
			reader,
			keybagOffset,
			keybagSize,
			containerIdentifier,
		)

		if err != nil {
			// If reading keybag fails, mark it as locked but don't fail the entire open
			keybag.IsLocked = true
		}

		c.Keybag = keybag
	}

	// Read space manager if present (only for debug output in C library)
	if DebugOutput && c.Superblock.SpacemanOID > 0 {
		// Get space manager block number from checkpoint map
		spaceManagerBlockNumber, err := c.CheckpointMap.PhysicalAddressByObjectIdentifier(c.Superblock.SpacemanOID)
		if err == nil {
			spaceManagerOffset := int64(spaceManagerBlockNumber) * int64(c.IOHandle.BlockSize)

			spaceManager := NewSpaceManager()
			err := spaceManager.ReadFrom(reader, spaceManagerOffset)
			if err != nil {
				// Don't fail container opening if space manager read fails (debug only)
				if DebugOutput {
					fmt.Printf("Warning: unable to read space manager: %v\n", err)
				}
			} else {
				c.SpaceManager = spaceManager
			}
		}
	}

	return nil
}

// Size retrieves the size of the container
func (c *Container) Size() (uint64, error) {
	if c == nil {
		return 0, fmt.Errorf("invalid container")
	}

	if c.IOHandle == nil {
		return 0, fmt.Errorf("invalid container - missing IO handle")
	}

	return c.IOHandle.ContainerSize, nil
}

// Identifier retrieves the container identifier (UUID)
func (c *Container) Identifier() ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("invalid container")
	}

	if c.Superblock == nil {
		return nil, fmt.Errorf("invalid container - missing superblock")
	}

	return c.Superblock.ContainerIdentifier()
}

// IsLocked checks if the container is locked (encrypted)
func (c *Container) IsLocked() (bool, error) {
	if c == nil {
		return false, fmt.Errorf("invalid container")
	}

	if c.Keybag == nil {
		// No keybag means no encryption
		return false, nil
	}

	return c.Keybag.IsLocked, nil
}

// NumberOfVolumes retrieves the number of volumes in the container
func (c *Container) NumberOfVolumes() (int, error) {
	if c == nil {
		return 0, fmt.Errorf("invalid container")
	}

	if c.Superblock == nil {
		return 0, fmt.Errorf("invalid container - missing superblock")
	}

	volumeIDs, err := c.Superblock.VolumeObjectIdentifiers()
	if err != nil {
		return 0, fmt.Errorf("unable to get volume object identifiers: %w", err)
	}

	return len(volumeIDs), nil
}

// VolumeObjectIdentifiers retrieves all volume object identifiers
func (c *Container) VolumeObjectIdentifiers() ([]uint64, error) {
	if c == nil {
		return nil, fmt.Errorf("invalid container")
	}

	if c.Superblock == nil {
		return nil, fmt.Errorf("invalid container - missing superblock")
	}

	return c.Superblock.VolumeObjectIdentifiers()
}

// Volume retrieves a volume by index
func (c *Container) Volume(index int) (*Volume, error) {
	if c == nil {
		return nil, fmt.Errorf("invalid container")
	}

	if c.Superblock == nil {
		return nil, fmt.Errorf("invalid container - missing superblock")
	}

	if c.ObjectMapBTree == nil {
		return nil, fmt.Errorf("invalid container - missing object map B-tree")
	}

	volumeIDs, err := c.VolumeObjectIdentifiers()
	if err != nil {
		return nil, fmt.Errorf("unable to get volume object identifiers: %w", err)
	}

	if index < 0 || index >= len(volumeIDs) {
		return nil, fmt.Errorf("volume index %d out of range (0-%d)", index, len(volumeIDs)-1)
	}

	volumeObjectID := volumeIDs[index]

	// Try checkpoint map first (for recent transactions), then object map B-tree
	// The checkpoint map contains mappings from the checkpoint descriptor area scan
	var physicalAddress uint64

	// First try the checkpoint map
	checkpointAddr, checkpointErr := c.CheckpointMap.PhysicalAddressByObjectIdentifier(volumeObjectID)
	if checkpointErr == nil && checkpointAddr != 0 {
		physicalAddress = checkpointAddr
	} else {
		// Fall back to object map B-tree for older transactions
		descriptor, err := c.ObjectMapBTree.DescriptorByObjectIdentifier(
			c.Reader,
			volumeObjectID,
			c.Superblock.XID,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to retrieve object map descriptor for volume object %d (transaction: %d): %w",
				volumeObjectID, c.Superblock.XID, err)
		}

		if descriptor == nil {
			return nil, fmt.Errorf("object map descriptor not found for volume object %d (transaction: %d)",
				volumeObjectID, c.Superblock.XID)
		}

		physicalAddress = descriptor.Value.ObjectPhysicalAddress
	}

	offset := int64(physicalAddress) * int64(c.IOHandle.BlockSize)

	if DebugOutput {
		fmt.Printf("Opening volume %d at offset %d (0x%08x)\n", index, offset, offset)
	}

	// Create and open volume
	volume, err := NewVolume(c.IOHandle, c.Reader, c.Keybag)
	if err != nil {
		return nil, fmt.Errorf("unable to create volume: %w", err)
	}

	// The passwords have to be in place before OpenRead, which is where an
	// encrypted volume is unlocked: everything it reads afterwards needs the
	// key.
	if c.userPassword != "" {
		volume.UserPassword = []byte(c.userPassword)
	}
	if c.recoveryPassword != "" {
		volume.RecoveryPassword = []byte(c.recoveryPassword)
	}

	err = volume.OpenRead(c.Reader, offset)
	if err != nil {
		volume.Close()
		return nil, fmt.Errorf("unable to open volume at offset %d: %w", offset, err)
	}

	return volume, nil
}
