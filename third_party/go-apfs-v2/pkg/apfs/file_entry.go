package apfs

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
)

// FileEntry represents an APFS file entry (file, directory, or special file)
type FileEntry struct {
	// IOHandle is the I/O handle
	IOHandle *IOHandle

	// FileHandle is the file I/O handle
	FileHandle io.ReaderAt

	// EncryptionContext is the encryption context
	EncryptionContext *EncryptionContext

	// FileSystemBTree is the file system B-tree
	FileSystemBTree *FileSystemBTree

	// Inode contains the inode metadata
	Inode *Inode

	// DirectoryEntryRecord contains the directory entry record (may be nil for root)
	DirectoryEntryRecord *DirectoryEntryRecord

	// XID is the transaction identifier
	XID uint64

	// ExtendedAttributes is the array of extended attributes (lazily initialized)
	ExtendedAttributes []*AttributeValues

	// CompressedDataAttributeValues holds com.apple.decmpfs attribute
	CompressedDataAttributeValues *AttributeValues

	// CompressedDataHeader contains the compressed data header
	CompressedDataHeader *CompressedDataHeader

	// ResourceForkAttributeValues holds com.apple.ResourceFork attribute
	ResourceForkAttributeValues *AttributeValues

	// SymbolicLinkAttributeValues holds com.apple.fs.symlink attribute
	SymbolicLinkAttributeValues *AttributeValues

	// SymbolicLinkData contains the symbolic link target data
	SymbolicLinkData []byte

	// DirectoryEntries contains sub-directory entries (lazily initialized)
	DirectoryEntries []*DirectoryEntryRecord

	// DataSize is the cached data size
	dataSize int64 // -1 indicates not yet determined

	// FileExtents contains the file extents (lazily initialized)
	FileExtents []*FileExtent

	// DataStream is the data stream (lazily initialized)
	DataStream *DataStream

	// currentOffset tracks the current read position
	currentOffset int64
}

// NewFileEntry creates a new file entry
func NewFileEntry(
	ioHandle *IOHandle,
	reader io.ReaderAt,
	encryptionContext *EncryptionContext,
	fileSystemBTree *FileSystemBTree,
	inode *Inode,
	directoryEntryRecord *DirectoryEntryRecord,
	xid uint64,
) (*FileEntry, error) {
	return &FileEntry{
		IOHandle:             ioHandle,
		FileHandle:           reader,
		EncryptionContext:    encryptionContext,
		FileSystemBTree:      fileSystemBTree,
		Inode:                inode,
		DirectoryEntryRecord: directoryEntryRecord,
		XID:                  xid,
		dataSize:             -1, // Not yet determined
		currentOffset:        0,
	}, nil
}

// Identifier retrieves the identifier
func (fe *FileEntry) Identifier() (uint64, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	return fe.Inode.Identifier, nil
}

// ParentIdentifier retrieves the parent identifier
func (fe *FileEntry) ParentIdentifier() (uint64, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	return fe.Inode.ParentIdentifier, nil
}

// ParentFileEntry retrieves the parent file entry
func (fe *FileEntry) ParentFileEntry() (*FileEntry, error) {
	if fe == nil {
		return nil, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return nil, fmt.Errorf("invalid inode")
	}

	if fe.FileSystemBTree == nil {
		return nil, fmt.Errorf("invalid file system B-tree")
	}

	parentIdentifier := fe.Inode.ParentIdentifier
	if parentIdentifier == 0 {
		return nil, nil // No parent (root)
	}

	// Get parent inode
	parentInode, err := fe.FileSystemBTree.InodeByIdentifier(
		fe.FileHandle,
		parentIdentifier,
		fe.XID,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve parent inode: %w", err)
	}

	// Get parent directory entry record (may be nil for root)
	// For now, we create the parent without a directory entry record
	return NewFileEntry(
		fe.IOHandle,
		fe.FileHandle,
		fe.EncryptionContext,
		fe.FileSystemBTree,
		parentInode,
		nil, // No directory entry record for parent
		fe.XID,
	)
}

// CreationTime retrieves the creation time
func (fe *FileEntry) CreationTime() (int64, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	// Convert from nanoseconds to seconds
	return int64(fe.Inode.CreationTime / 1000000000), nil
}

// ModificationTime retrieves the modification time
func (fe *FileEntry) ModificationTime() (int64, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	// Convert from nanoseconds to seconds
	return int64(fe.Inode.ModificationTime / 1000000000), nil
}

// AccessTime retrieves the access time
func (fe *FileEntry) AccessTime() (int64, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	// Convert from nanoseconds to seconds
	return int64(fe.Inode.AccessTime / 1000000000), nil
}

// InodeChangeTime retrieves the inode change time
func (fe *FileEntry) InodeChangeTime() (int64, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	// Convert from nanoseconds to seconds
	return int64(fe.Inode.InodeChangeTime / 1000000000), nil
}

// AddedTime retrieves the added time (from directory entry record)
func (fe *FileEntry) AddedTime() (int64, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.DirectoryEntryRecord == nil {
		return 0, fmt.Errorf("invalid directory entry record")
	}

	return int64(fe.DirectoryEntryRecord.AddedTime), nil
}

// OwnerIdentifier retrieves the owner identifier (UID)
func (fe *FileEntry) OwnerIdentifier() (uint32, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	return fe.Inode.OwnerIdentifier, nil
}

// GroupIdentifier retrieves the group identifier (GID)
func (fe *FileEntry) GroupIdentifier() (uint32, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	return fe.Inode.GroupIdentifier, nil
}

// DeviceIdentifier retrieves the device identifier
func (fe *FileEntry) DeviceIdentifier() (uint32, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	return fe.Inode.DeviceIdentifier, nil
}

// DeviceNumber retrieves the major and minor device numbers
func (fe *FileEntry) DeviceNumber() (major uint32, minor uint32, err error) {
	if fe == nil {
		return 0, 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, 0, fmt.Errorf("invalid inode")
	}

	// Extract major and minor from device identifier
	// Major is upper 8 bits, minor is lower 24 bits
	major = (fe.Inode.DeviceIdentifier >> 24) & 0xFF
	minor = fe.Inode.DeviceIdentifier & 0xFFFFFF

	return major, minor, nil
}

// FileMode retrieves the file mode (permissions and type)
func (fe *FileEntry) FileMode() (uint16, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	return fe.Inode.FileMode, nil
}

// NumberOfLinks retrieves the number of hard links
func (fe *FileEntry) NumberOfLinks() (uint32, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	return fe.Inode.NumberOfLinks, nil
}

// BSDFlags retrieves the inode's chflags(2) flags. Test it against the
// BSDFlag* constants; BSDFlagCompressed is the one that says the content lives
// in com.apple.decmpfs rather than the data fork.
func (fe *FileEntry) BSDFlags() (uint32, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	return fe.Inode.BSDFlags, nil
}

// UTF8NameSize retrieves the size of the UTF-8 encoded name
func (fe *FileEntry) UTF8NameSize() (int, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.DirectoryEntryRecord != nil {
		return fe.DirectoryEntryRecord.UTF8NameSize()
	}

	// For root or entries without directory entry record, use inode name
	if fe.Inode != nil && fe.Inode.Name != nil {
		return len(fe.Inode.Name) + 1, nil // +1 for null terminator
	}

	return 0, fmt.Errorf("no name available")
}

// UTF8Name retrieves the UTF-8 encoded name
func (fe *FileEntry) UTF8Name() (string, error) {
	if fe == nil {
		return "", fmt.Errorf("invalid file entry")
	}

	if fe.DirectoryEntryRecord != nil {
		return fe.DirectoryEntryRecord.UTF8Name()
	}

	// For root or entries without directory entry record, use inode name
	if fe.Inode != nil && fe.Inode.Name != nil {
		return string(fe.Inode.Name), nil
	}

	return "", fmt.Errorf("no name available")
}

// UTF16NameSize retrieves the size of the UTF-16 encoded name
func (fe *FileEntry) UTF16NameSize() (int, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	if fe.DirectoryEntryRecord != nil {
		return fe.DirectoryEntryRecord.UTF16NameSize()
	}

	// For root or entries without directory entry record, use inode name
	if fe.Inode != nil && fe.Inode.Name != nil {
		// Count UTF-16 code units
		utf16Count := 0
		nameBytes := fe.Inode.Name
		for len(nameBytes) > 0 {
			r, size := utf8.DecodeRune(nameBytes)
			if r == utf8.RuneError {
				return 0, fmt.Errorf("invalid UTF-8 sequence")
			}
			if r <= 0xFFFF {
				utf16Count++
			} else {
				utf16Count += 2 // Surrogate pair
			}
			nameBytes = nameBytes[size:]
		}
		return utf16Count + 1, nil // +1 for null terminator
	}

	return 0, fmt.Errorf("no name available")
}

// UTF16Name retrieves the UTF-16 encoded name
func (fe *FileEntry) UTF16Name() ([]uint16, error) {
	if fe == nil {
		return nil, fmt.Errorf("invalid file entry")
	}

	if fe.DirectoryEntryRecord != nil {
		return fe.DirectoryEntryRecord.UTF16Name()
	}

	// For root or entries without directory entry record, use inode name
	if fe.Inode != nil && fe.Inode.Name != nil {
		runes := []rune(string(fe.Inode.Name))
		return utf16.Encode(runes), nil
	}

	return nil, fmt.Errorf("no name available")
}

// getExtendedAttributes retrieves the extended attributes (lazy initialization)
func (fe *FileEntry) getExtendedAttributes() error {
	if fe.ExtendedAttributes != nil {
		return nil
	}

	if fe.Inode == nil {
		return fmt.Errorf("invalid inode")
	}

	if fe.FileSystemBTree == nil {
		return fmt.Errorf("invalid file system B-tree")
	}

	// Get extended attributes from the file system B-tree
	attributes, err := fe.FileSystemBTree.Attributes(
		fe.FileHandle,
		fe.Inode.Identifier,
		fe.XID,
	)
	if err != nil {
		return fmt.Errorf("unable to retrieve extended attributes: %w", err)
	}

	fe.ExtendedAttributes = attributes

	// Look for special attributes
	for _, attr := range attributes {
		name := attr.NameString()
		switch name {
		case "com.apple.decmpfs":
			fe.CompressedDataAttributeValues = attr
		case "com.apple.ResourceFork":
			fe.ResourceForkAttributeValues = attr
		case "com.apple.fs.symlink":
			fe.SymbolicLinkAttributeValues = attr
		}
	}

	return nil
}

// NumberOfExtendedAttributes retrieves the number of extended attributes
func (fe *FileEntry) NumberOfExtendedAttributes() (int, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	// Ensure extended attributes are loaded
	if err := fe.getExtendedAttributes(); err != nil {
		return 0, fmt.Errorf("unable to retrieve extended attributes: %w", err)
	}

	return len(fe.ExtendedAttributes), nil
}

// ExtendedAttributeByIndex retrieves an extended attribute by index
func (fe *FileEntry) ExtendedAttributeByIndex(index int) (*ExtendedAttribute, error) {
	if fe == nil {
		return nil, fmt.Errorf("invalid file entry")
	}

	// Ensure extended attributes are loaded
	if err := fe.getExtendedAttributes(); err != nil {
		return nil, fmt.Errorf("unable to retrieve extended attributes: %w", err)
	}

	if index < 0 || index >= len(fe.ExtendedAttributes) {
		return nil, fmt.Errorf("invalid extended attribute index: %d", index)
	}

	// Create extended attribute from attribute values
	return NewExtendedAttribute(
		fe.IOHandle,
		fe.FileHandle,
		fe.EncryptionContext,
		fe.FileSystemBTree,
		fe.ExtendedAttributes[index],
		fe.XID,
	)
}

// HasExtendedAttributeByName checks if an extended attribute exists by name
func (fe *FileEntry) HasExtendedAttributeByName(name string) (bool, error) {
	if fe == nil {
		return false, fmt.Errorf("invalid file entry")
	}

	// Ensure extended attributes are loaded
	if err := fe.getExtendedAttributes(); err != nil {
		return false, fmt.Errorf("unable to retrieve extended attributes: %w", err)
	}

	for _, attr := range fe.ExtendedAttributes {
		if attr.NameString() == name {
			return true, nil
		}
	}

	return false, nil
}

// ExtendedAttributeByName retrieves an extended attribute by name
func (fe *FileEntry) ExtendedAttributeByName(name string) (*ExtendedAttribute, error) {
	if fe == nil {
		return nil, fmt.Errorf("invalid file entry")
	}

	// Ensure extended attributes are loaded
	if err := fe.getExtendedAttributes(); err != nil {
		return nil, fmt.Errorf("unable to retrieve extended attributes: %w", err)
	}

	for _, attr := range fe.ExtendedAttributes {
		if attr.NameString() == name {
			// Create extended attribute from attribute values
			return NewExtendedAttribute(
				fe.IOHandle,
				fe.FileHandle,
				fe.EncryptionContext,
				fe.FileSystemBTree,
				attr,
				fe.XID,
			)
		}
	}

	return nil, fmt.Errorf("extended attribute not found: %s", name)
}

// HasExtendedAttributeByUTF16Name checks if an extended attribute exists by UTF-16 name
func (fe *FileEntry) HasExtendedAttributeByUTF16Name(utf16Name []uint16) (bool, error) {
	if fe == nil {
		return false, fmt.Errorf("invalid file entry")
	}

	// Convert UTF-16 to UTF-8
	runes := utf16.Decode(utf16Name)
	name := string(runes)

	return fe.HasExtendedAttributeByName(name)
}

// ExtendedAttributeByUTF16Name retrieves an extended attribute by UTF-16 name
func (fe *FileEntry) ExtendedAttributeByUTF16Name(utf16Name []uint16) (*ExtendedAttribute, error) {
	if fe == nil {
		return nil, fmt.Errorf("invalid file entry")
	}

	// Convert UTF-16 to UTF-8
	runes := utf16.Decode(utf16Name)
	name := string(runes)

	return fe.ExtendedAttributeByName(name)
}

// getSymbolicLinkData retrieves the symbolic link data (lazy initialization)
func (fe *FileEntry) getSymbolicLinkData() error {
	if fe.SymbolicLinkData != nil {
		return nil
	}

	// Ensure extended attributes are loaded
	if err := fe.getExtendedAttributes(); err != nil {
		return fmt.Errorf("unable to retrieve extended attributes: %w", err)
	}

	if fe.SymbolicLinkAttributeValues == nil {
		return fmt.Errorf("no symbolic link attribute")
	}

	// Get data stream from symbolic link attribute
	dataStream, err := fe.SymbolicLinkAttributeValues.DataStream(
		fe.IOHandle,
		fe.FileHandle,
		fe.EncryptionContext,
		fe.FileSystemBTree,
		fe.XID,
	)
	if err != nil {
		return fmt.Errorf("unable to retrieve symbolic link data stream: %w", err)
	}

	if dataStream == nil {
		return fmt.Errorf("no symbolic link data stream")
	}

	// Read symbolic link data
	size := dataStream.Size()
	fe.SymbolicLinkData = make([]byte, size)
	n, err := dataStream.ReadAt(fe.SymbolicLinkData, 0)
	if err != nil && err != io.EOF {
		return fmt.Errorf("unable to read symbolic link data: %w", err)
	}
	if n != int(size) {
		return fmt.Errorf("unable to read symbolic link data: read %d bytes, expected %d", n, size)
	}

	return nil
}

// SymbolicLinkTargetSize retrieves the size of the symbolic link target
func (fe *FileEntry) SymbolicLinkTargetSize() (int, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	// Ensure symbolic link data is loaded
	if err := fe.getSymbolicLinkData(); err != nil {
		return 0, fmt.Errorf("unable to retrieve symbolic link data: %w", err)
	}

	return len(fe.SymbolicLinkData) + 1, nil // +1 for null terminator
}

// SymbolicLinkTarget retrieves the symbolic link target
func (fe *FileEntry) SymbolicLinkTarget() (string, error) {
	if fe == nil {
		return "", fmt.Errorf("invalid file entry")
	}

	// Ensure symbolic link data is loaded
	if err := fe.getSymbolicLinkData(); err != nil {
		return "", fmt.Errorf("unable to retrieve symbolic link data: %w", err)
	}

	// Trim trailing null bytes and spaces to prevent "invalid argument" errors
	// when creating symlinks on the file system
	target := string(fe.SymbolicLinkData)
	target = strings.TrimRight(target, "\x00 \t\r\n")

	return target, nil
}

// SymbolicLinkTargetUTF16Size retrieves the size of the UTF-16 encoded symbolic link target
func (fe *FileEntry) SymbolicLinkTargetUTF16Size() (int, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	// Ensure symbolic link data is loaded
	if err := fe.getSymbolicLinkData(); err != nil {
		return 0, fmt.Errorf("unable to retrieve symbolic link data: %w", err)
	}

	// Count UTF-16 code units
	utf16Count := 0
	linkBytes := fe.SymbolicLinkData
	for len(linkBytes) > 0 {
		r, size := utf8.DecodeRune(linkBytes)
		if r == utf8.RuneError {
			return 0, fmt.Errorf("invalid UTF-8 sequence")
		}
		if r <= 0xFFFF {
			utf16Count++
		} else {
			utf16Count += 2 // Surrogate pair
		}
		linkBytes = linkBytes[size:]
	}

	return utf16Count + 1, nil // +1 for null terminator
}

// SymbolicLinkTargetUTF16 retrieves the UTF-16 encoded symbolic link target
func (fe *FileEntry) SymbolicLinkTargetUTF16() ([]uint16, error) {
	if fe == nil {
		return nil, fmt.Errorf("invalid file entry")
	}

	// Ensure symbolic link data is loaded
	if err := fe.getSymbolicLinkData(); err != nil {
		return nil, fmt.Errorf("unable to retrieve symbolic link data: %w", err)
	}

	runes := []rune(string(fe.SymbolicLinkData))
	return utf16.Encode(runes), nil
}

// getDirectoryEntries retrieves the directory entries (lazy initialization)
func (fe *FileEntry) getDirectoryEntries() error {
	if fe.DirectoryEntries != nil {
		return nil
	}

	if fe.Inode == nil {
		return fmt.Errorf("invalid inode")
	}

	if fe.FileSystemBTree == nil {
		return fmt.Errorf("invalid file system B-tree")
	}

	// Get directory entries from the file system B-tree
	entries, err := fe.FileSystemBTree.DirectoryEntries(
		fe.FileHandle,
		fe.Inode.Identifier,
		fe.XID,
	)
	if err != nil {
		return fmt.Errorf("unable to retrieve directory entries: %w", err)
	}

	fe.DirectoryEntries = entries
	return nil
}

// NumberOfSubFileEntries retrieves the number of sub-file entries (directory children)
func (fe *FileEntry) NumberOfSubFileEntries() (int, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	// Ensure directory entries are loaded
	if err := fe.getDirectoryEntries(); err != nil {
		return 0, fmt.Errorf("unable to retrieve directory entries: %w", err)
	}

	return len(fe.DirectoryEntries), nil
}

// SubFileEntryByIndex retrieves a sub-file entry by index
func (fe *FileEntry) SubFileEntryByIndex(index int) (*FileEntry, error) {
	if fe == nil {
		return nil, fmt.Errorf("invalid file entry")
	}

	// Ensure directory entries are loaded
	if err := fe.getDirectoryEntries(); err != nil {
		return nil, fmt.Errorf("unable to retrieve directory entries: %w", err)
	}

	if index < 0 || index >= len(fe.DirectoryEntries) {
		return nil, fmt.Errorf("invalid sub-file entry index: %d", index)
	}

	directoryEntryRecord := fe.DirectoryEntries[index]

	// Get inode for this directory entry
	inode, err := fe.FileSystemBTree.InodeByIdentifier(
		fe.FileHandle,
		directoryEntryRecord.Identifier,
		fe.XID,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve inode for identifier %d: %w", directoryEntryRecord.Identifier, err)
	}

	// Create file entry
	return NewFileEntry(
		fe.IOHandle,
		fe.FileHandle,
		fe.EncryptionContext,
		fe.FileSystemBTree,
		inode,
		directoryEntryRecord,
		fe.XID,
	)
}

// SubFileEntryByName retrieves a sub-file entry by name
func (fe *FileEntry) SubFileEntryByName(name string) (*FileEntry, error) {
	if fe == nil {
		return nil, fmt.Errorf("invalid file entry")
	}

	// Ensure directory entries are loaded
	if err := fe.getDirectoryEntries(); err != nil {
		return nil, fmt.Errorf("unable to retrieve directory entries: %w", err)
	}

	for _, directoryEntryRecord := range fe.DirectoryEntries {
		entryName, err := directoryEntryRecord.UTF8Name()
		if err != nil {
			continue
		}

		if entryName == name {
			// Get inode for this directory entry
			inode, err := fe.FileSystemBTree.InodeByIdentifier(
				fe.FileHandle,
				directoryEntryRecord.Identifier,
				fe.XID,
			)
			if err != nil {
				return nil, fmt.Errorf("unable to retrieve inode for identifier %d: %w", directoryEntryRecord.Identifier, err)
			}

			// Create file entry
			return NewFileEntry(
				fe.IOHandle,
				fe.FileHandle,
				fe.EncryptionContext,
				fe.FileSystemBTree,
				inode,
				directoryEntryRecord,
				fe.XID,
			)
		}
	}

	return nil, fmt.Errorf("sub-file entry not found: %s", name)
}

// SubFileEntryByUTF16Name retrieves a sub-file entry by UTF-16 name
func (fe *FileEntry) SubFileEntryByUTF16Name(utf16Name []uint16) (*FileEntry, error) {
	if fe == nil {
		return nil, fmt.Errorf("invalid file entry")
	}

	// Convert UTF-16 to UTF-8
	runes := utf16.Decode(utf16Name)
	name := string(runes)

	return fe.SubFileEntryByName(name)
}

// getFileExtents retrieves the file extents (lazy initialization)
func (fe *FileEntry) getFileExtents() error {
	if fe.FileExtents != nil {
		return nil
	}

	if fe.Inode == nil {
		return fmt.Errorf("invalid inode")
	}

	if fe.FileSystemBTree == nil {
		return fmt.Errorf("invalid file system B-tree")
	}

	// Get file extents from the file system B-tree
	// First try using the inode identifier (most common case)
	extents, err := fe.FileSystemBTree.FileExtents(
		fe.FileHandle,
		fe.Inode.Identifier,
		fe.XID,
	)
	if err != nil {
		return fmt.Errorf("unable to retrieve file extents: %w", err)
	}

	// If no extents found and DataStreamIdentifier is set, try using that
	// This handles files where data is stored via a separate data stream
	if len(extents) == 0 && fe.Inode.DataStreamIdentifier != 0 {
		extents, err = fe.FileSystemBTree.FileExtents(
			fe.FileHandle,
			fe.Inode.DataStreamIdentifier,
			fe.XID,
		)
		if err != nil {
			return fmt.Errorf("unable to retrieve file extents via data stream ID: %w", err)
		}
	}

	fe.FileExtents = extents
	return nil
}

// internalCompressionMethod maps a raw com.apple.decmpfs type to the internal
// compression method codes. The mapping is shared with the HFS+ reader, so it
// lives in internal/decmpfs; this wrapper is kept because it names the
// operation in this package's terms and is what the tests here exercise.
func internalCompressionMethod(decmpfsType uint32) (int, error) {
	return decmpfs.MethodFor(decmpfsType)
}

// newInlineDecmpfsStream builds the decompressing stream for a com.apple.decmpfs
// attribute that stores its compressed data inline, immediately after the
// 16-byte header, rather than in a resource fork.
//
// attrValue must be the *whole* attribute value, header included; see
// decmpfs.CheckInline for why, and what goes wrong when it is stripped.
func newInlineDecmpfsStream(
	attrValue []byte,
	uncompressedSize uint64,
	method int,
	fileHandle io.ReaderAt,
) (*DataStream, error) {
	if err := decmpfs.CheckInline(attrValue); err != nil {
		return nil, err
	}

	compressedDataStream, err := NewDataStreamFromData(attrValue)
	if err != nil {
		return nil, fmt.Errorf("unable to create compressed data stream from embedded data: %w", err)
	}

	dataStream, err := NewDataStreamFromCompressedDataStream(compressedDataStream, uncompressedSize, method)
	if err != nil {
		return nil, fmt.Errorf("unable to create decompressed data stream: %w", err)
	}

	if cdReader, ok := dataStream.readerAt.(*compressedDataReader); ok {
		cdReader.SetFileHandle(fileHandle)
	}
	return dataStream, nil
}

// getDataStream retrieves the data stream (lazy initialization)
func (fe *FileEntry) getDataStream() error {
	if fe.DataStream != nil {
		return nil
	}

	// UF_COMPRESSED, rather than the presence of an attribute, selects storage.
	if fe.Inode != nil && fe.Inode.BSDFlags&BSDFlagCompressed != 0 {
		var err error
		fe.DataStream, err = fe.compressedStream()
		return err
	}

	// Try to get file extents for normal files
	if err := fe.getFileExtents(); err != nil {
		return fmt.Errorf("unable to retrieve file extents: %w", err)
	}

	if len(fe.FileExtents) == 0 {
		// Check if this is a zero-length file
		size, err := fe.DataSize()
		if err == nil && size == 0 {
			// Create empty data stream for zero-length files
			dataStream, err := NewDataStreamFromData([]byte{})
			if err != nil {
				return fmt.Errorf("unable to create empty data stream: %w", err)
			}
			fe.DataStream = dataStream
			return nil
		}

		// A DataStreamIdentifier of 0 may mean inline data in the inode,
		// which is not supported; it falls through to the error below.

		return fmt.Errorf("no file extents and no compressed data")
	}

	// Get data size
	size, err := fe.DataSize()
	if err != nil {
		return fmt.Errorf("unable to get data size: %w", err)
	}

	// Create data stream from file extents
	dataStream, err := NewDataStreamFromFileExtents(
		fe.IOHandle,
		fe.EncryptionContext,
		fe.FileExtents,
		uint64(size),
		false, // Not sparse
	)
	if err != nil {
		return fmt.Errorf("unable to create data stream from file extents: %w", err)
	}

	// Set the file handle for the data stream reader
	if dbReader, ok := dataStream.readerAt.(*dataBlockReader); ok {
		dbReader.SetFileHandle(fe.FileHandle)
	}

	fe.DataStream = dataStream
	return nil
}

// Read reads data at the current offset into a buffer
func (fe *FileEntry) Read(buffer []byte) (int, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	// Ensure data stream is initialized
	if err := fe.getDataStream(); err != nil {
		return 0, fmt.Errorf("unable to determine data stream: %w", err)
	}

	// Read from data stream at current offset
	n, err := fe.DataStream.ReadAt(buffer, fe.currentOffset)
	if err != nil && err != io.EOF {
		return n, fmt.Errorf("unable to read buffer from data stream: %w", err)
	}

	// Update current offset
	fe.currentOffset += int64(n)

	return n, err
}

// ReadAt reads data at a specific offset
func (fe *FileEntry) ReadAt(buffer []byte, offset int64) (int, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	// Ensure data stream is initialized
	if err := fe.getDataStream(); err != nil {
		return 0, fmt.Errorf("unable to determine data stream: %w", err)
	}

	// Read from data stream at specified offset
	n, err := fe.DataStream.ReadAt(buffer, offset)
	if err != nil && err != io.EOF {
		return n, fmt.Errorf("unable to read buffer at offset from data stream: %w", err)
	}

	return n, err
}

// Seek seeks to a certain offset
func (fe *FileEntry) Seek(offset int64, whence int) (int64, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	// Get the data size for calculations
	size, err := fe.DataSize()
	if err != nil {
		return 0, fmt.Errorf("unable to get data size: %w", err)
	}

	// Calculate new offset based on whence
	var newOffset int64
	switch whence {
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset = fe.currentOffset + offset
	case io.SeekEnd:
		newOffset = size + offset
	default:
		return 0, fmt.Errorf("invalid whence value: %d", whence)
	}

	// Validate new offset
	if newOffset < 0 {
		return 0, fmt.Errorf("invalid offset value out of bounds")
	}

	fe.currentOffset = newOffset
	return newOffset, nil
}

// Offset retrieves the current offset
func (fe *FileEntry) Offset() (int64, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	return fe.currentOffset, nil
}

// DataSize retrieves the data size (lazy calculation)
func (fe *FileEntry) DataSize() (int64, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	// Return cached value if available
	if fe.dataSize != -1 {
		return fe.dataSize, nil
	}

	if fe.Inode == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	if fe.Inode.BSDFlags&BSDFlagCompressed != 0 {
		_, header, err := fe.compressionAttribute()
		if err != nil {
			return 0, err
		}
		fe.dataSize = int64(header.UncompressedDataSize)
		return fe.dataSize, nil
	}

	// Use data stream size from inode
	fe.dataSize = int64(fe.Inode.DataStreamSize)
	return fe.dataSize, nil
}

// Size retrieves the size
func (fe *FileEntry) Size() (uint64, error) {
	size, err := fe.DataSize()
	if err != nil {
		return 0, err
	}
	return uint64(size), nil
}

// NumberOfExtents retrieves the number of extents
func (fe *FileEntry) NumberOfExtents() (int, error) {
	if fe == nil {
		return 0, fmt.Errorf("invalid file entry")
	}

	// Ensure file extents are loaded
	if err := fe.getFileExtents(); err != nil {
		return 0, fmt.Errorf("unable to retrieve file extents: %w", err)
	}

	return len(fe.FileExtents), nil
}

// ExtentByIndex retrieves an extent by index
func (fe *FileEntry) ExtentByIndex(index int) (offset int64, size uint64, flags uint32, err error) {
	if fe == nil {
		return 0, 0, 0, fmt.Errorf("invalid file entry")
	}

	// Ensure file extents are loaded
	if err := fe.getFileExtents(); err != nil {
		return 0, 0, 0, fmt.Errorf("unable to retrieve file extents: %w", err)
	}

	if index < 0 || index >= len(fe.FileExtents) {
		return 0, 0, 0, fmt.Errorf("invalid extent index: %d", index)
	}

	extent := fe.FileExtents[index]

	// Calculate physical offset (physical block number * block size)
	physicalOffset := int64(extent.PhysicalBlockNumber * 4096)

	// Data size is already in bytes
	dataSize := extent.DataSize

	// Flags currently return 0 (not stored separately in FileExtent)
	extentFlags := uint32(0)

	return physicalOffset, dataSize, extentFlags, nil
}
