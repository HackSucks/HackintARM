// APFS definitions and constants
package apfs

// Version is the version of this package.
const Version = "1.0.0"

// AccessFlags represents file access modes
// Corresponds to LIBFSAPFS_ACCESS_FLAGS
type AccessFlags int

const (
	// AccessFlagRead indicates read access (bit 1)
	AccessFlagRead AccessFlags = 0x01
	// AccessFlagWrite indicates write access (bit 2) - Reserved: not supported yet
	AccessFlagWrite AccessFlags = 0x02
)

// File access modes
const (
	// OpenRead opens for read access
	OpenRead = AccessFlagRead
	// OpenWrite opens for write access - Reserved: not supported yet
	OpenWrite = AccessFlagWrite
	// OpenReadWrite opens for read and write access - Reserved: not supported yet
	OpenReadWrite = AccessFlagRead | AccessFlagWrite
)

// PathSeparator is the path segment separator
const PathSeparator = '/'

// FileType represents APFS file types
// Corresponds to LIBFSAPFS_FILE_TYPES
type FileType uint16

const (
	// FileTypeFIFO represents a FIFO/named pipe
	FileTypeFIFO FileType = 0x1000
	// FileTypeCharacterDevice represents a character device
	FileTypeCharacterDevice FileType = 0x2000
	// FileTypeDirectory represents a directory
	FileTypeDirectory FileType = 0x4000
	// FileTypeBlockDevice represents a block device
	FileTypeBlockDevice FileType = 0x6000
	// FileTypeRegularFile represents a regular file
	FileTypeRegularFile FileType = 0x8000
	// FileTypeSymbolicLink represents a symbolic link
	FileTypeSymbolicLink FileType = 0xa000
	// FileTypeSocket represents a socket
	FileTypeSocket FileType = 0xc000
)

// Compression method constants are defined in compressed_data_handle.go
// Corresponds to LIBFSAPFS_COMPRESSION_METHODS

// CryptMode represents encryption/decryption modes
// Corresponds to LIBFSAPFS_ENCRYPTION_CRYPT_MODES
type CryptMode int

const (
	// CryptModeDecrypt indicates decryption mode
	CryptModeDecrypt CryptMode = 0
	// CryptModeEncrypt indicates encryption mode
	CryptModeEncrypt CryptMode = 1
)

// EncryptionMethod represents encryption methods
// Corresponds to LIBFSAPFS_ENCRYPTION_METHODS
type EncryptionMethod int

const (
	// EncryptionMethodAES256XTS represents AES-256-XTS encryption
	EncryptionMethodAES256XTS EncryptionMethod = 0
	// EncryptionMethodAES128XTS represents AES-128-XTS encryption
	EncryptionMethodAES128XTS EncryptionMethod = 2
)

// FileSystemRecordType constants are defined in btree_key_value.go
// Corresponds to LIBFSAPFS_FILE_SYSTEM_DATA_TYPES

// Cache size limits
const (
	// MaximumCacheEntriesBTreeNodes is the maximum number of cached B-tree nodes
	MaximumCacheEntriesBTreeNodes = 8192
	// MaximumCacheEntriesDataBlocks is the maximum number of cached data blocks
	MaximumCacheEntriesDataBlocks = 16
)

// MaxBTreeNodeDepth is the maximum B-tree node recursion depth
const MaxBTreeNodeDepth = 256

// Byte order constants
const (
	// EndianBig represents big-endian byte order
	EndianBig = 1
	// EndianLittle represents little-endian byte order
	EndianLittle = 0
)
