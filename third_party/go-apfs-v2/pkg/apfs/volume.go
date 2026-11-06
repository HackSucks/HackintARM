// Volume functions
package apfs

import (
	"fmt"
	"io"
)

// Volume represents an APFS volume
type Volume struct {
	// The volume superblock
	Superblock *VolumeSuperblock

	// The volume object map B-tree
	ObjectMapBTree *ObjectMapBTree

	// The file system B-tree
	FileSystemBTree *FileSystemBTree

	// The extentref tree (optional)
	ExtentrefTree *ExtentrefTree

	// The snapshot metadata tree (optional)
	SnapshotMetadataTree *SnapshotMetadataTree

	// The volume's own keybag, holding the key-encryption keys a password
	// unwraps. Nil when the volume is not encrypted, or when its keybag could
	// not be located or parsed — in which case the volume stays locked.
	VolumeKeybag *VolumeKeybag

	// The encryption context (optional)
	EncryptionContext *EncryptionContext

	// The IO handle
	IOHandle *IOHandle

	// The file IO handle
	Reader io.ReaderAt

	// The container keybag reference
	ContainerKeybag *ContainerKeybag

	// The container data handle
	ContainerDataHandle *ContainerDataHandle

	// Value to indicate if the volume is locked (private to avoid conflict with IsLocked method)
	isLocked bool

	// The user password (for encrypted volumes)
	UserPassword []byte

	// The recovery password (for encrypted volumes)
	RecoveryPassword []byte
}

// NewVolume creates a new volume
func NewVolume(
	ioHandle *IOHandle,
	reader io.ReaderAt,
	containerKeybag *ContainerKeybag,
) (*Volume, error) {
	if ioHandle == nil {
		return nil, fmt.Errorf("invalid IO handle")
	}
	if reader == nil {
		return nil, fmt.Errorf("invalid reader")
	}

	return &Volume{
		IOHandle:        ioHandle,
		Reader:          reader,
		ContainerKeybag: containerKeybag,
	}, nil
}

// OpenRead opens a volume for reading
func (v *Volume) OpenRead(reader io.ReaderAt, fileOffset int64) error {
	if v == nil {
		return fmt.Errorf("invalid volume")
	}
	if v.IOHandle == nil {
		return fmt.Errorf("invalid volume - missing IO handle")
	}
	if v.Superblock != nil {
		return fmt.Errorf("invalid volume - superblock already set")
	}

	if DebugOutput {
		fmt.Println("Reading volume superblock")
	}

	// Read volume superblock
	volumeSuperblock := NewVolumeSuperblock()
	if volumeSuperblock == nil {
		return fmt.Errorf("unable to create volume superblock")
	}

	if err := volumeSuperblock.ReadFrom(reader, fileOffset, false); err != nil {
		return fmt.Errorf("unable to read volume superblock at offset %d (0x%08x): %w",
			fileOffset, fileOffset, err)
	}

	v.Superblock = volumeSuperblock

	// Create container data handle
	containerDataHandle, err := NewContainerDataHandle(v.IOHandle)
	if err != nil {
		return fmt.Errorf("unable to create container data handle: %w", err)
	}
	v.ContainerDataHandle = containerDataHandle

	// Read object map
	if v.Superblock.OmapOID == 0 {
		return fmt.Errorf("missing object map block number")
	}

	if DebugOutput {
		fmt.Println("Reading volume object map")
	}

	objectMapOffset := int64(v.Superblock.OmapOID) * int64(v.IOHandle.BlockSize)

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

	if DebugOutput {
		fmt.Println("Reading volume object map B-tree")
	}

	// Read the volume's keybag and, if a password unlocks it, build the context
	// that decrypts everything read below. An encrypted volume that stays
	// locked is not an error here: OpenRead's job is to report what the volume
	// is, and IsLocked is how a caller finds out. Reading its contents is what
	// must refuse.
	if err := v.openEncryption(reader); err != nil {
		return err
	}
	encryptionContext := v.EncryptionContext

	// The object map is not encrypted, even on a FileVault volume: it maps
	// object ids to block numbers, which gives nothing away, and the driver
	// needs it before any key is available. Only the file-system tree and file
	// contents are enciphered. Handing the context to the object map here
	// would decrypt plaintext into noise -- verified against a volume encrypted
	// by diskutil, whose object-map root reads as a valid B-tree node with a
	// correct Fletcher-64 checksum before any decryption.
	objectMapBTree, err := NewObjectMapBTree(
		v.IOHandle,
		nil,
		objectMap.TreeOID,
	)
	if err != nil {
		return fmt.Errorf("unable to create object map B-tree: %w", err)
	}
	v.ObjectMapBTree = objectMapBTree

	// Free the object map as we only needed it to get the B-tree block number

	// Read file system B-tree
	fileSystemRootObjectID := v.Superblock.RootTreeOID
	if fileSystemRootObjectID == 0 {
		return fmt.Errorf("missing file system root object identifier")
	}

	if DebugOutput {
		fmt.Println("Reading file system B-tree")
	}

	fileSystemBTree := NewFileSystemBTree(
		v.IOHandle,
		encryptionContext,
		objectMapBTree,
		fileSystemRootObjectID,
		v.Superblock.XID, // Volume's transaction ID
		v.Superblock.IncompatibleFeaturesFlags&VolumeIncompatCaseInsensitive != 0,
	)
	// A sealed volume keeps its file extents in a separate physical tree.
	fileSystemBTree.FextTreeOID = v.Superblock.FextTreeOID
	fileSystemBTree.FextTreeType = v.Superblock.FextTreeType
	v.FileSystemBTree = fileSystemBTree

	// Read extentref tree if present
	if v.Superblock.ExtentrefTreeOID > 0 {
		if DebugOutput {
			fmt.Println("Reading extentref tree")
		}

		extentrefTree := NewExtentrefTree()

		// Calculate offset and read extentref tree data
		extentReferenceTreeOffset := int64(v.Superblock.ExtentrefTreeOID) * int64(v.IOHandle.BlockSize)

		if err := extentrefTree.ReadFrom(reader, extentReferenceTreeOffset); err != nil {
			// Extent reference tree read failure is not fatal - volume can still be used
			// This matches the C library behavior which continues on read failure
			if DebugOutput {
				fmt.Printf("Warning: unable to read extentref tree: %v\n", err)
			}
		}

		v.ExtentrefTree = extentrefTree
	}

	// Read snapshot metadata tree if present
	if v.Superblock.SnapMetaTreeOID > 0 {
		if DebugOutput {
			fmt.Println("Reading snapshot metadata tree")
		}

		snapshotMetadataTree, err := NewSnapshotMetadataTree(
			v.IOHandle,
			objectMapBTree,
			v.Superblock.SnapMetaTreeOID,
		)
		if err != nil {
			return fmt.Errorf("unable to create snapshot metadata tree: %w", err)
		}
		v.SnapshotMetadataTree = snapshotMetadataTree
	}

	return nil
}

// Close closes a volume
func (v *Volume) Close() error {
	if v == nil {
		return fmt.Errorf("invalid volume")
	}
	if v.IOHandle == nil {
		return fmt.Errorf("invalid volume - missing IO handle")
	}

	// Clear file IO handle reference
	v.Reader = nil

	// Free snapshot metadata tree
	if v.SnapshotMetadataTree != nil {

		v.SnapshotMetadataTree = nil
	}

	// Free extentref tree
	if v.ExtentrefTree != nil {

		v.ExtentrefTree = nil
	}

	// Free file system B-tree
	if v.FileSystemBTree != nil {

		v.FileSystemBTree = nil
	}

	// Free encryption context
	if v.EncryptionContext != nil {

		v.EncryptionContext = nil
	}

	// Free volume keybag
	if v.VolumeKeybag != nil {
		v.VolumeKeybag.Close()
		v.VolumeKeybag = nil
	}

	// Free object map B-tree
	if v.ObjectMapBTree != nil {
		v.ObjectMapBTree = nil
	}

	// Free container data handle
	if v.ContainerDataHandle != nil {
		v.ContainerDataHandle = nil
	}

	// Free volume superblock
	if v.Superblock != nil {
		v.Superblock = nil
	}

	return nil
}

// UTF8NameSize retrieves the size of the UTF-8 encoded volume name
// The returned size includes the end of string character
func (v *Volume) UTF8NameSize() (int, error) {
	if v == nil {
		return 0, fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return 0, fmt.Errorf("invalid volume - missing superblock")
	}

	return v.Superblock.UTF8VolumeNameSize()
}

// UTF8Name retrieves the UTF-8 encoded volume name
func (v *Volume) UTF8Name() (string, error) {
	if v == nil {
		return "", fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return "", fmt.Errorf("invalid volume - missing superblock")
	}

	return v.Superblock.UTF8VolumeName()
}

// UTF16NameSize retrieves the size of the UTF-16 encoded volume name
// The returned size includes the end of string character
func (v *Volume) UTF16NameSize() (int, error) {
	if v == nil {
		return 0, fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return 0, fmt.Errorf("invalid volume - missing superblock")
	}

	return v.Superblock.UTF16VolumeNameSize()
}

// UTF16Name retrieves the UTF-16 encoded volume name
func (v *Volume) UTF16Name() ([]uint16, error) {
	if v == nil {
		return nil, fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return nil, fmt.Errorf("invalid volume - missing superblock")
	}

	return v.Superblock.UTF16VolumeName()
}

// Identifier retrieves the volume identifier (UUID)
func (v *Volume) Identifier() ([16]byte, error) {
	if v == nil {
		return [16]byte{}, fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return [16]byte{}, fmt.Errorf("invalid volume - missing superblock")
	}

	return v.Superblock.VolumeIdentifier()
}

// IsLocked reports whether the volume is encrypted and has not been unlocked,
// so its contents cannot be read.
//
// This is the check a caller must make before reading anything: a locked
// volume's metadata is ciphertext, and parsing it produces structural errors
// that say nothing about the real cause.
func (v *Volume) IsLocked() (bool, error) {
	if v == nil {
		return false, fmt.Errorf("invalid volume")
	}
	return v.isLocked, nil
}

// NumberOfSnapshots retrieves the number of snapshots
func (v *Volume) NumberOfSnapshots() (int, error) {
	if v == nil {
		return 0, fmt.Errorf("invalid volume")
	}

	if v.SnapshotMetadataTree == nil {
		return 0, nil
	}

	return v.SnapshotMetadataTree.NumberOfEntries(v.Reader)
}

// Snapshot retrieves a snapshot by index
func (v *Volume) Snapshot(index int) (*Snapshot, error) {
	if v == nil {
		return nil, fmt.Errorf("invalid volume")
	}

	if v.SnapshotMetadataTree == nil {
		return nil, fmt.Errorf("no snapshot metadata tree")
	}

	// Get snapshot metadata by index
	snapshotMetadata, err := v.SnapshotMetadataTree.EntryByIndex(v.Reader, index)
	if err != nil {
		return nil, fmt.Errorf("unable to get snapshot metadata at index %d: %w", index, err)
	}

	// Create snapshot
	snapshot, err := NewSnapshot(v.IOHandle, v.Reader, snapshotMetadata)
	if err != nil {
		return nil, fmt.Errorf("unable to create snapshot: %w", err)
	}

	// The snapshot's volume superblock is a physical object, so sblock_oid is its
	// block number directly (not an object-map-resolved virtual oid).
	blockNumber := snapshotMetadata.VolumeSuperblockOID

	// Open snapshot (reads volume superblock)
	offset := int64(blockNumber) * int64(v.IOHandle.BlockSize)
	err = snapshot.OpenRead(v.Reader, offset)
	if err != nil {
		snapshot.Close()
		return nil, fmt.Errorf("unable to open snapshot: %w", err)
	}

	return snapshot, nil
}

// RootDirectory retrieves the root directory file entry.
//
// The root is ROOT_DIR_INO_NUM on every volume, including the system volume of
// a volume group: only the user inode numbers move into the group's upper half.
// See apfswrite.inoBaseFor for how that was established.
func (v *Volume) RootDirectory() (*FileEntry, error) {
	if v == nil {
		return nil, fmt.Errorf("invalid volume")
	}

	if v.FileSystemBTree == nil {
		return nil, fmt.Errorf("invalid volume - missing file system B-tree")
	}

	return v.FileEntryByIdentifier(RootDirInoNum)
}

// FileEntryByIdentifier retrieves a file entry by inode number
func (v *Volume) FileEntryByIdentifier(identifier uint64) (*FileEntry, error) {
	if v == nil {
		return nil, fmt.Errorf("invalid volume")
	}

	if v.FileSystemBTree == nil {
		return nil, fmt.Errorf("invalid volume - missing file system B-tree")
	}

	// Get inode from file system B-tree
	inode, err := v.FileSystemBTree.InodeByIdentifier(v.Reader, identifier, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to get inode %d: %w", identifier, err)
	}

	if inode == nil {
		return nil, fmt.Errorf("inode %d not found", identifier)
	}

	// Create file entry from inode
	// Note: Using NewFileEntry with all required parameters
	fileEntry, err := NewFileEntry(
		v.IOHandle,
		v.Reader,
		v.EncryptionContext,
		v.FileSystemBTree,
		inode,
		nil, // directory entry record - not available when accessing by identifier
		inode.ParentIdentifier,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create file entry: %w", err)
	}

	return fileEntry, nil
}

// FileEntryByPath retrieves a file entry by path
func (v *Volume) FileEntryByPath(path string) (*FileEntry, error) {
	if v == nil {
		return nil, fmt.Errorf("invalid volume")
	}

	if v.FileSystemBTree == nil {
		return nil, fmt.Errorf("invalid volume - missing file system B-tree")
	}

	// If path is empty or root, return root directory
	if path == "" || path == "/" {
		return v.RootDirectory()
	}

	// Use FileSystemBTree.InodeByUTF8Path to traverse the path, starting from
	// the root directory rather than ROOT_DIR_PARENT, which is the virtual
	// parent the two special dentries hang off.
	inode, directoryEntryRecord, err := v.FileSystemBTree.InodeByUTF8Path(
		v.Reader,
		RootDirInoNum,
		path,
		0, // transaction identifier
	)
	if err != nil {
		return nil, fmt.Errorf("unable to get inode by path %s: %w", path, err)
	}

	if inode == nil {
		return nil, fmt.Errorf("path not found: %s", path)
	}

	// Create file entry from inode and directory entry record
	fileEntry, err := NewFileEntry(
		v.IOHandle,
		v.Reader,
		v.EncryptionContext,
		v.FileSystemBTree,
		inode,
		directoryEntryRecord,
		inode.ParentIdentifier,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create file entry: %w", err)
	}

	return fileEntry, nil
}

// SetUTF8Password sets the user password for unlocking an encrypted volume
// This function must be called before Unlock() for password-based unlocking
func (v *Volume) SetUTF8Password(password []byte) error {
	if v == nil {
		return fmt.Errorf("invalid volume")
	}

	if password == nil {
		return fmt.Errorf("invalid password")
	}

	// Clear existing password if set
	if v.UserPassword != nil {
		// Zero out the old password for security
		for i := range v.UserPassword {
			v.UserPassword[i] = 0
		}
		v.UserPassword = nil
	}

	// Store a copy of the password
	v.UserPassword = make([]byte, len(password))
	copy(v.UserPassword, password)

	if isVerbose() {
		notifyPrintf("SetUTF8Password: password set (length: %d)\n", len(password))
	}

	return nil
}

// SetUTF16Password sets the user password from UTF-16 encoding
func (v *Volume) SetUTF16Password(utf16Password []uint16) error {
	if v == nil {
		return fmt.Errorf("invalid volume")
	}

	if utf16Password == nil {
		return fmt.Errorf("invalid password")
	}

	// Convert UTF-16 to UTF-8
	utf8Password := []byte(UTF16ToString(utf16Password))

	return v.SetUTF8Password(utf8Password)
}

// SetUTF8RecoveryPassword sets the recovery password for unlocking an encrypted volume
// This function must be called before Unlock() for recovery password-based unlocking
func (v *Volume) SetUTF8RecoveryPassword(password []byte) error {
	if v == nil {
		return fmt.Errorf("invalid volume")
	}

	if password == nil {
		return fmt.Errorf("invalid password")
	}

	// Clear existing recovery password if set
	if v.RecoveryPassword != nil {
		// Zero out the old password for security
		for i := range v.RecoveryPassword {
			v.RecoveryPassword[i] = 0
		}
		v.RecoveryPassword = nil
	}

	// Store a copy of the password
	v.RecoveryPassword = make([]byte, len(password))
	copy(v.RecoveryPassword, password)

	if isVerbose() {
		notifyPrintf("SetUTF8RecoveryPassword: recovery password set (length: %d)\n", len(password))
	}

	return nil
}

// SetUTF16RecoveryPassword sets the recovery password from UTF-16 encoding
func (v *Volume) SetUTF16RecoveryPassword(utf16Password []uint16) error {
	if v == nil {
		return fmt.Errorf("invalid volume")
	}

	if utf16Password == nil {
		return fmt.Errorf("invalid password")
	}

	// Convert UTF-16 to UTF-8
	utf8Password := []byte(UTF16ToString(utf16Password))

	return v.SetUTF8RecoveryPassword(utf8Password)
}

// FeaturesFlags retrieves the volume feature flags
func (v *Volume) FeaturesFlags() (compatible, incompatible, readOnlyCompatible uint64, err error) {
	if v == nil {
		return 0, 0, 0, fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return 0, 0, 0, fmt.Errorf("invalid volume - missing superblock")
	}

	compatible = v.Superblock.CompatibleFeaturesFlags
	incompatible = v.Superblock.IncompatibleFeaturesFlags
	readOnlyCompatible = v.Superblock.ReadOnlyCompatibleFeaturesFlags

	return compatible, incompatible, readOnlyCompatible, nil
}

// Size retrieves the size of the volume in bytes
func (v *Volume) Size() (uint64, error) {
	if v == nil {
		return 0, fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return 0, fmt.Errorf("invalid volume - missing superblock")
	}

	if v.IOHandle == nil {
		return 0, fmt.Errorf("invalid volume - missing IO handle")
	}

	// Calculate volume size from allocated blocks (apfs_fs_alloc_count field)
	// This represents the number of blocks currently allocated on this volume
	volumeSize := v.Superblock.NumberOfAllocatedBlocks * uint64(v.IOHandle.BlockSize)

	return volumeSize, nil
}

// NextFileEntryIdentifier retrieves the next file entry identifier
func (v *Volume) NextFileEntryIdentifier() (uint64, error) {
	if v == nil {
		return 0, fmt.Errorf("invalid volume")
	}

	if v.Superblock == nil {
		return 0, fmt.Errorf("invalid volume - missing superblock")
	}

	// Note: The superblock may not directly expose NextOID
	// In the C library, this traverses the file system B-tree to find the highest inode
	// For now, return an error indicating this needs B-tree traversal
	return 0, fmt.Errorf("GetNextFileEntryIdentifier requires B-tree traversal - not yet implemented")
}
