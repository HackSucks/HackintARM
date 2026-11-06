// Inode functions
package apfs

import (
	"encoding/binary"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v2/internal/common"
)

// Reserved inode numbers. All inode numbers below MinUserInoNum are reserved.
const (
	InvalidInoNum uint64 = 0 // INVALID_INO_NUM
	RootDirParent uint64 = 1 // ROOT_DIR_PARENT, the root directory's parent
	RootDirInoNum uint64 = 2 // ROOT_DIR_INO_NUM
	PrivDirInoNum uint64 = 3 // PRIV_DIR_INO_NUM, the private directory
	MinUserInoNum uint64 = 16
)

// UnifiedIDSpaceMark (UNIFIED_ID_SPACE_MARK) divides the inode-number space the
// two members of a volume group share: the data volume numbers below it, the
// system volume at or above it, so a number identifies a file across the pair.
//
// The reserved numbers above are not shifted by it. The spec says they are, but
// fsck_apfs rejects a volume written that way; see inoBaseFor in pkg/apfswrite.
const UnifiedIDSpaceMark uint64 = 0x0800000000000000

// BSD file flags (chflags(2)) as stored in an inode's bsd_flags field.
const (
	// BSDFlagCompressed is UF_COMPRESSED: the file's content is held by its
	// com.apple.decmpfs attribute rather than by its data fork, which is empty.
	//
	// macOS dispatches on this flag. Without it the ordinary data fork is
	// authoritative, including an empty fork; decmpfs attributes are inactive.
	BSDFlagCompressed uint32 = 0x00000020
)

// Inode represents an APFS inode (file or directory metadata)
type Inode struct {
	// The identifier
	Identifier uint64

	// The parent identifier
	ParentIdentifier uint64

	// The modification time (nanoseconds since Unix epoch)
	ModificationTime uint64

	// The creation time (nanoseconds since Unix epoch)
	CreationTime uint64

	// The inode change time (nanoseconds since Unix epoch)
	InodeChangeTime uint64

	// The access time (nanoseconds since Unix epoch)
	AccessTime uint64

	// The owner identifier (UID)
	OwnerIdentifier uint32

	// The group identifier (GID)
	GroupIdentifier uint32

	// Device identifier
	DeviceIdentifier uint32

	// The file mode (permissions and type)
	FileMode uint16

	// Number of (hard) links
	NumberOfLinks uint32

	// BSDFlags is the inode's chflags(2) flags (bsd_flags). Use the BSDFlag*
	// constants. UF_COMPRESSED is the one that changes how the file is read:
	// it says the content is held by com.apple.decmpfs rather than by the data
	// fork.
	BSDFlags uint32

	// The name
	Name []byte

	// The inode flags
	Flags uint64

	// The data stream identifier
	DataStreamIdentifier uint64

	// The data stream size
	DataStreamSize uint64
}

// NewInode creates a new inode
func NewInode() (*Inode, error) {
	return &Inode{}, nil
}

// Close releases resources associated with the inode
func (i *Inode) Close() error {
	if i == nil {
		return fmt.Errorf("invalid inode")
	}

	// Go's garbage collector will handle memory cleanup
	i.Name = nil

	return nil
}

// ReadKeyData reads the inode key data from a B-tree entry
func (i *Inode) ReadKeyData(data []byte) error {
	if i == nil {
		return fmt.Errorf("invalid inode")
	}

	if len(data) < 8 {
		return fmt.Errorf("invalid key data size: expected at least 8 bytes, got %d", len(data))
	}

	// Debug output
	if isVerbose() {
		notifyPrintf("Inode key data:\n")
		PrintData(data, true)
	}

	// Read file system identifier (contains the object ID and type)
	fileSystemIdentifier := binary.LittleEndian.Uint64(data[0:8])

	// Debug output
	if isVerbose() {
		notifyPrintf("identifier\t\t\t\t: 0x%08x\n", fileSystemIdentifier)
		notifyPrintf("\n")
	}

	// Extract the identifier (lower 60 bits)
	i.Identifier = fileSystemIdentifier & 0x0fffffffffffffff

	return nil
}

// ReadValueData reads the inode value data from a B-tree entry
func (i *Inode) ReadValueData(data []byte) error {
	if i == nil {
		return fmt.Errorf("invalid inode")
	}

	if i.Name != nil {
		return fmt.Errorf("invalid inode - name value already set")
	}

	// FileSystemBTreeValueInode is variable size, minimum is the fixed part
	// Per drat's j_inode_val_t: parent_id(8) + private_id(8) + create_time(8) + mod_time(8) +
	// change_time(8) + access_time(8) + internal_flags(8) + nchildren/nlink(4) +
	// default_protection_class(4) + write_generation_counter(4) + bsd_flags(4) +
	// owner(4) + group(4) + mode(2) + pad1(2) + uncompressed_size(8) = 92 bytes
	const minInodeValueSize = 92

	if len(data) < minInodeValueSize || len(data) > common.Int32Max {
		return fmt.Errorf("invalid value data size value out of bounds (len=%d, min=%d, max=%d)", len(data), minInodeValueSize, common.Int32Max)
	}

	// Debug output
	if isVerbose() {
		notifyPrintf("Inode value data:\n")
		PrintData(data, true)
	}

	// Read fixed fields (per drat's j_inode_val_t)
	i.ParentIdentifier = binary.LittleEndian.Uint64(data[0:8])      // parent_id
	i.DataStreamIdentifier = binary.LittleEndian.Uint64(data[8:16]) // private_id
	i.CreationTime = binary.LittleEndian.Uint64(data[16:24])        // create_time
	i.ModificationTime = binary.LittleEndian.Uint64(data[24:32])    // mod_time
	i.InodeChangeTime = binary.LittleEndian.Uint64(data[32:40])     // change_time
	i.AccessTime = binary.LittleEndian.Uint64(data[40:48])          // access_time
	i.Flags = binary.LittleEndian.Uint64(data[48:56])               // internal_flags
	i.NumberOfLinks = binary.LittleEndian.Uint32(data[56:60])       // nchildren/nlink
	// Skip: default_protection_class (60:64), write_generation_counter (64:68)
	i.BSDFlags = binary.LittleEndian.Uint32(data[68:72])        // bsd_flags
	i.OwnerIdentifier = binary.LittleEndian.Uint32(data[72:76]) // owner
	i.GroupIdentifier = binary.LittleEndian.Uint32(data[76:80]) // group
	i.FileMode = binary.LittleEndian.Uint16(data[80:82])        // mode
	// Skip: pad1 (82-84), uncompressed_size (84-92)
	// Extended fields (xfields[]) start at offset 92

	// Debug output
	if isVerbose() {
		notifyPrintf("parent identifier\t\t\t: %d\n", i.ParentIdentifier)
		notifyPrintf("data stream identifier\t\t\t: %d\n", i.DataStreamIdentifier)

		timeBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(timeBytes, i.ModificationTime)
		_ = PrintPOSIXTimeValue("Inode.ReadValueData", "modification time\t\t\t", timeBytes, binary.LittleEndian, "nanoseconds")

		binary.LittleEndian.PutUint64(timeBytes, i.CreationTime)
		_ = PrintPOSIXTimeValue("Inode.ReadValueData", "creation time\t\t\t\t", timeBytes, binary.LittleEndian, "nanoseconds")

		binary.LittleEndian.PutUint64(timeBytes, i.InodeChangeTime)
		_ = PrintPOSIXTimeValue("Inode.ReadValueData", "inode change time\t\t\t", timeBytes, binary.LittleEndian, "nanoseconds")

		binary.LittleEndian.PutUint64(timeBytes, i.AccessTime)
		_ = PrintPOSIXTimeValue("Inode.ReadValueData", "access time\t\t\t\t", timeBytes, binary.LittleEndian, "nanoseconds")

		notifyPrintf("inode flags\t\t\t\t: 0x%08x\n", i.Flags)
		PrintInodeFlags(i.Flags)
		notifyPrintf("\n")

		if (i.FileMode & 0xf000) == uint16(FileTypeDirectory) {
			notifyPrintf("number of children\t\t\t: %d\n", i.NumberOfLinks)
		} else {
			notifyPrintf("number of links\t\t\t: %d\n", i.NumberOfLinks)
		}

		notifyPrintf("owner identifier\t\t\t: %d\n", i.OwnerIdentifier)
		notifyPrintf("group identifier\t\t\t: %d\n", i.GroupIdentifier)
		notifyPrintf("file mode\t\t\t\t: %o\n", i.FileMode)
	}

	// Parse extended fields if present
	// Per drat's xf.h: xf_num_exts (2 bytes), xf_used_data (2 bytes), then xf_data[]
	if len(data) > minInodeValueSize {
		dataOffset := minInodeValueSize

		if dataOffset > (len(data) - 4) {
			return fmt.Errorf("invalid data size value out of bounds")
		}

		numberOfExtendedFields := binary.LittleEndian.Uint16(data[dataOffset : dataOffset+2])
		extendedFieldValueDataSize := binary.LittleEndian.Uint16(data[dataOffset+2 : dataOffset+4])

		if isVerbose() {
			notifyPrintf("number of extended fields\t\t: %d\n", numberOfExtendedFields)
			notifyPrintf("extended field value data size\t\t: %d\n", extendedFieldValueDataSize)
		}

		dataOffset += 4
		valueDataOffset := dataOffset + (int(numberOfExtendedFields) * 4)

		for extendedFieldIndex := uint16(0); extendedFieldIndex < numberOfExtendedFields; extendedFieldIndex++ {
			if dataOffset > (len(data) - 4) {
				return fmt.Errorf("invalid data size value out of bounds")
			}

			extendedFieldType := data[dataOffset]
			extendedFieldFlags := data[dataOffset+1]
			valueDataSize := binary.LittleEndian.Uint16(data[dataOffset+2 : dataOffset+4])

			if isVerbose() {
				notifyPrintf("extended field: %d type\t\t\t: %d %s\n", extendedFieldIndex, extendedFieldType, InodeExtendedFieldTypeName(extendedFieldType))
				notifyPrintf("extended field: %d flags\t\t: 0x%02x\n", extendedFieldIndex, extendedFieldFlags)
				PrintExtendedFieldFlags(extendedFieldFlags)
				notifyPrintf("\n")
				notifyPrintf("extended field: %d value data size\t: %d\n", extendedFieldIndex, valueDataSize)
			}

			dataOffset += 4

			if valueDataOffset > len(data) {
				return fmt.Errorf("invalid data size value out of bounds (offset=%d, len=%d)", valueDataOffset, len(data))
			}

			if valueDataSize == 0 || int(valueDataSize) > (len(data)-valueDataOffset) {
				return fmt.Errorf("invalid value data size value out of bounds (field %d: type=%d, size=%d, offset=%d, data_len=%d, remaining=%d)",
					extendedFieldIndex, extendedFieldType, valueDataSize, valueDataOffset, len(data), len(data)-valueDataOffset)
			}

			valueData := data[valueDataOffset : valueDataOffset+int(valueDataSize)]

			if isVerbose() {
				notifyPrintf("extended field: %d value data:\n", extendedFieldIndex)
				PrintData(valueData, false)
			}

			// Parse specific extended field types
			switch extendedFieldType {
			case 1, 2, 3, 5, 7, 10, 11, 13, 15:
				// These are defined in the spec but not currently parsed

			case 4: // INO_EXT_TYPE_NAME
				// Name extended field
				if i.Name != nil {
					return fmt.Errorf("invalid inode - name value already set")
				}

				i.Name = make([]byte, valueDataSize)
				copy(i.Name, valueData)

				if isVerbose() {
					notifyPrintf("name\t\t\t\t\t: %s\n", string(i.Name))
				}

			case 8: // INO_EXT_TYPE_DSTREAM
				// Data stream attribute
				// j_dstream_t: size(8) + alloced_size(8) + default_crypto_id(8) +
				// total_bytes_written(8) + total_bytes_read(8) = 40 bytes
				const dataStreamAttrSize = 40
				if valueDataSize < dataStreamAttrSize {
					return fmt.Errorf("invalid value data size value out of bounds (DSTREAM: size=%d, expected_min=%d)", valueDataSize, dataStreamAttrSize)
				}

				i.DataStreamSize = binary.LittleEndian.Uint64(valueData[0:8])

				if isVerbose() {
					notifyPrintf("used size\t\t\t\t: %d\n", i.DataStreamSize)
					allocatedSize := binary.LittleEndian.Uint64(valueData[8:16])
					notifyPrintf("allocated size\t\t\t\t: %d\n", allocatedSize)
					encryptionIdentifier := binary.LittleEndian.Uint64(valueData[16:24])
					notifyPrintf("encryption identifier\t\t\t: %d\n", encryptionIdentifier)
					bytesWritten := binary.LittleEndian.Uint64(valueData[24:32])
					notifyPrintf("number of bytes written\t\t: %d\n", bytesWritten)
					bytesRead := binary.LittleEndian.Uint64(valueData[32:40])
					notifyPrintf("number of bytes read\t\t\t: %d\n", bytesRead)
					notifyPrintf("\n")
				}

			case 14: // INO_EXT_TYPE_RDEV
				// Device identifier
				if valueDataSize != 4 {
					return fmt.Errorf("invalid value data size value out of bounds (RDEV: size=%d, expected=4)", valueDataSize)
				}

				i.DeviceIdentifier = binary.LittleEndian.Uint32(valueData[0:4])

				if isVerbose() {
					notifyPrintf("device identifier\t\t\t: 0x%08x\n", i.DeviceIdentifier)
					notifyPrintf("\n")
				}

			default:
				return fmt.Errorf("unsupported extended field type: %d", extendedFieldType)
			}

			valueDataOffset += int(valueDataSize)

			// Handle padding (8-byte alignment)
			trailingDataSize := int(valueDataSize) % 8
			if trailingDataSize > 0 {
				trailingDataSize = 8 - trailingDataSize

				if valueDataOffset > (len(data) - trailingDataSize) {
					trailingDataSize = len(data) - valueDataOffset
				}

				if isVerbose() && trailingDataSize > 0 {
					notifyPrintf("extended field: %d trailing data:\n", extendedFieldIndex)
					PrintData(data[valueDataOffset:valueDataOffset+trailingDataSize], false)
				}

				valueDataOffset += trailingDataSize
			}
		}
	} else if isVerbose() {
		notifyPrintf("\n")
	}

	return nil
}

// DeviceNumber retrieves the device number
func (i *Inode) DeviceNumber() (uint32, uint32, error) {
	if i == nil {
		return 0, 0, fmt.Errorf("invalid inode")
	}

	// Extract major and minor device numbers from device identifier
	majorDeviceNumber := (i.DeviceIdentifier >> 24) & common.Uint8Mask
	minorDeviceNumber := i.DeviceIdentifier & common.Uint24Mask

	return majorDeviceNumber, minorDeviceNumber, nil
}

// UTF8NameSize retrieves the UTF-8 name size
func (i *Inode) UTF8NameSize() (int, error) {
	if i == nil {
		return 0, fmt.Errorf("invalid inode")
	}

	if i.Name == nil {
		return 0, nil
	}

	// Return size including null terminator
	return len(i.Name) + 1, nil
}

// UTF8Name retrieves the UTF-8 name
func (i *Inode) UTF8Name() ([]byte, error) {
	if i == nil {
		return nil, fmt.Errorf("invalid inode")
	}

	if i.Name == nil {
		return nil, fmt.Errorf("invalid inode - name not set")
	}

	// Return a copy to prevent external modification
	name := make([]byte, len(i.Name))
	copy(name, i.Name)

	return name, nil
}

// IsDirectory returns true if this inode represents a directory
func (i *Inode) IsDirectory() bool {
	return (i.FileMode & 0xf000) == uint16(FileTypeDirectory)
}

// IsRegularFile returns true if this inode represents a regular file
func (i *Inode) IsRegularFile() bool {
	return (i.FileMode & 0xf000) == uint16(FileTypeRegularFile)
}

// IsSymbolicLink returns true if this inode represents a symbolic link
func (i *Inode) IsSymbolicLink() bool {
	return (i.FileMode & 0xf000) == uint16(FileTypeSymbolicLink)
}

// Permissions returns the permission bits (lower 12 bits of file mode)
func (i *Inode) Permissions() uint16 {
	return i.FileMode & 0x0fff
}

// FileType returns the file type bits (upper 4 bits of file mode)
func (i *Inode) FileType() uint16 {
	return i.FileMode & 0xf000
}
