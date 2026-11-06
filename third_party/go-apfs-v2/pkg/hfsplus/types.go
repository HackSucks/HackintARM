// On-disk structure definitions for HFS Plus / HFSX volumes.
//
// The catalog and B-tree type definitions in this file are adapted from
// blacktop/go-apfs's hfsplus package (Apache-2.0):
// https://github.com/blacktop/go-apfs/tree/main/pkg/disk/hfsplus
//
// Reference: Apple Technote TN1150 "HFS Plus Volume Format"
// https://developer.apple.com/library/archive/technotes/tn/tn1150.html
package hfsplus

import (
	"fmt"
	"time"
	"unicode/utf16"
)

// Signature identifies the volume format in the volume header.
type Signature uint16

const (
	HFSPlusSigWord Signature = 0x482B // "H+"
	HFSXSigWord    Signature = 0x4858 // "HX"
)

func (s Signature) String() string {
	switch s {
	case HFSPlusSigWord:
		return "HFS+"
	case HFSXSigWord:
		return "HFSX"
	default:
		return fmt.Sprintf("unknown(%#04x)", uint16(s))
	}
}

const (
	// HFSPlusVersion is the only valid version for 'H+' volumes.
	HFSPlusVersion uint16 = 4
	// HFSXVersion is the first valid version for 'HX' volumes.
	HFSXVersion uint16 = 5

	// Indirect node files (hard links) have this Finder type/creator.
	HardLinkFileType uint32 = 0x686C6E6B // 'hlnk'
	HFSPlusCreator   uint32 = 0x6866732B // 'hfs+'

	// Directory hard links have this Finder type/creator.
	DirLinkFileType uint32 = 0x66647270 // 'fdrp'
	DirLinkCreator  uint32 = 0x4D414353 // 'MACS'

	// Symbolic links have this Finder type/creator.
	SymLinkFileType uint32 = 0x736C6E6B // 'slnk'
	SymLinkCreator  uint32 = 0x72686170 // 'rhap'
)

// HFS Plus volume attribute masks (subset).
const (
	HFSVolumeUnmountedMask    = 0x00000100
	HFSVolumeJournaledMask    = 0x00002000
	HFSVolumeInconsistentMask = 0x00004000
	HFSVolumeSoftwareLockMask = 0x00008000
)

// hfsTime is seconds since midnight, January 1, 1904, GMT.
type hfsTime uint32

func (t hfsTime) Time() time.Time {
	hfsEpoch := time.Date(1904, time.January, 1, 0, 0, 0, 0, time.UTC)
	return hfsEpoch.Add(time.Duration(t) * time.Second)
}

// UniStr255 is an HFS Plus Unicode (UTF-16BE) string, stored fully
// decomposed and in canonical order.
type UniStr255 struct {
	Length  uint16
	UniChar []uint16
}

func (us *UniStr255) String() string {
	n := int(us.Length)
	if n > len(us.UniChar) {
		n = len(us.UniChar)
	}
	return string(utf16.Decode(us.UniChar[:n]))
}

// BSDInfo holds the POSIX permission info of a catalog record.
type BSDInfo struct {
	OwnerID    uint32
	GroupID    uint32
	AdminFlags uint8
	OwnerFlags uint8
	FileMode   uint16
	// Special is a union: iNodeNum for hard links, linkCount for indirect
	// node files, rawDevice for block/character devices.
	Special uint32
}

// BSD file mode bits (FileMode & S_IFMT).
const (
	sIFMT   = 0xF000
	sIFIFO  = 0x1000
	sIFCHR  = 0x2000
	sIFDIR  = 0x4000
	sIFBLK  = 0x6000
	sIFREG  = 0x8000
	sIFLNK  = 0xA000
	sIFSOCK = 0xC000
)

// chflags(2) bits as stored in BSDInfo.OwnerFlags.
const (
	// ufImmutable is UF_IMMUTABLE. macOS sets it on hard-link records and on
	// the private metadata directory, which exist to be followed rather than
	// changed.
	ufImmutable = 0x02
	// ufCompressed is UF_COMPRESSED: decmpfs transparent compression.
	ufCompressed = 0x20
)

// CatalogNodeID identifies a file or folder in the catalog.
type CatalogNodeID uint32

const (
	HFSRootParentID     CatalogNodeID = 1 // parent of the root folder
	HFSRootFolderID     CatalogNodeID = 2 // the root folder itself
	HFSExtentsFileID    CatalogNodeID = 3 // extents overflow file
	HFSCatalogFileID    CatalogNodeID = 4 // catalog file
	HFSBadBlockFileID   CatalogNodeID = 5 // bad allocation block file
	HFSAllocationFileID CatalogNodeID = 6 // allocation bitmap file
	HFSStartupFileID    CatalogNodeID = 7 // startup file
	HFSAttributesFileID CatalogNodeID = 8 // attributes file

	HFSFirstUserCatalogNodeID CatalogNodeID = 16
)

// ExtentDescriptor describes one contiguous run of allocation blocks.
type ExtentDescriptor struct {
	StartBlock uint32
	BlockCount uint32
}

// HFSPlusExtentDensity is the number of extents stored inline per fork.
const HFSPlusExtentDensity = 8

// ExtentRecord is the inline extent list of a fork (or one extents
// overflow leaf record).
type ExtentRecord [HFSPlusExtentDensity]ExtentDescriptor

// ForkData describes the size and initial extents of a file fork.
type ForkData struct {
	LogicalSize uint64
	ClumpSize   uint32
	TotalBlocks uint32
	Extents     ExtentRecord
}

// VolumeHeader is the 512-byte HFS Plus volume header at offset 1024.
type VolumeHeader struct {
	Signature          Signature
	Version            uint16
	Attributes         uint32
	LastMountedVersion [4]byte
	JournalInfoBlock   uint32
	CreateDate         hfsTime
	ModifyDate         hfsTime
	BackupDate         hfsTime
	CheckedDate        hfsTime
	FileCount          uint32
	FolderCount        uint32
	BlockSize          uint32
	TotalBlocks        uint32
	FreeBlocks         uint32
	NextAllocation     uint32
	RsrcClumpSize      uint32
	DataClumpSize      uint32
	NextCatalogID      CatalogNodeID
	WriteCount         uint32
	EncodingsBitmap    uint64
	FinderInfo         [8]uint32
	AllocationFile     ForkData
	ExtentsFile        ForkData
	CatalogFile        ForkData
	AttributesFile     ForkData
	StartupFile        ForkData
}

/* Catalog records */

// Point and Rect are classic Finder geometry types.
type Point struct {
	V int16
	H int16
}

type Rect struct {
	Top    int16
	Left   int16
	Bottom int16
	Right  int16
}

// FolderInfo is the Finder info of a folder record.
type FolderInfo struct {
	WindowBounds Rect
	FinderFlags  uint16
	Location     Point
	Opaque       uint16
}

// FinderFileInfo is the Finder info of a file record.
type FinderFileInfo struct {
	FileType    uint32 // OSType
	FileCreator uint32 // OSType
	FinderFlags uint16
	Location    Point
	Opaque      uint16
}

// FinderOpaqueInfo is the extended Finder info blob.
type FinderOpaqueInfo struct {
	Opaque [16]int8
}

// RecordType discriminates catalog leaf records.
type RecordType int16

const (
	HFSPlusFolderRecord       RecordType = 0x0001
	HFSPlusFileRecord         RecordType = 0x0002
	HFSPlusFolderThreadRecord RecordType = 0x0003
	HFSPlusFileThreadRecord   RecordType = 0x0004
)

// CatalogFlags are the flag bits of catalog file/folder records.
type CatalogFlags uint16

const (
	HFSFileLockedMask     CatalogFlags = 0x0001
	HFSThreadExistsMask   CatalogFlags = 0x0002
	HFSHasAttributesMask  CatalogFlags = 0x0004
	HFSHasSecurityMask    CatalogFlags = 0x0008
	HFSHasFolderCountMask CatalogFlags = 0x0010
	HFSHasLinkChainMask   CatalogFlags = 0x0020
	HFSHasChildLinkMask   CatalogFlags = 0x0040
	HFSHasDateAddedMask   CatalogFlags = 0x0080
)

// HFSPlusCatalogFolder is an HFS Plus catalog folder record (88 bytes).
type HFSPlusCatalogFolder struct {
	RecordType       RecordType
	Flags            CatalogFlags
	Valence          uint32
	FolderID         CatalogNodeID
	CreateDate       hfsTime
	ContentModDate   hfsTime
	AttributeModDate hfsTime
	AccessDate       hfsTime
	BackupDate       hfsTime
	BSDInfo          BSDInfo
	UserInfo         FolderInfo
	FinderInfo       FinderOpaqueInfo
	TextEncoding     uint32
	FolderCount      uint32
}

// HFSPlusCatalogFile is an HFS Plus catalog file record (248 bytes).
type HFSPlusCatalogFile struct {
	RecordType       RecordType
	Flags            CatalogFlags
	Reserved1        uint32
	FileID           CatalogNodeID
	CreateDate       hfsTime
	ContentModDate   hfsTime
	AttributeModDate hfsTime
	AccessDate       hfsTime
	BackupDate       hfsTime
	BSDInfo          BSDInfo
	UserInfo         FinderFileInfo
	FinderInfo       FinderOpaqueInfo
	TextEncoding     uint32
	Reserved2        uint32
	DataFork         ForkData
	ResourceFork     ForkData
}

// CatalogKey is the key of a catalog B-tree record.
type CatalogKey struct {
	KeyLength uint16
	ParentID  CatalogNodeID
	NodeName  UniStr255
}

/* B-tree structures */

// BTreeNodeKind is the kind byte of a B-tree node descriptor.
type BTreeNodeKind int8

const (
	BTLeafNodeKind   BTreeNodeKind = -1
	BTIndexNodeKind  BTreeNodeKind = 0
	BTHeaderNodeKind BTreeNodeKind = 1
	BTMapNodeKind    BTreeNodeKind = 2
)

func (kind BTreeNodeKind) String() string {
	switch kind {
	case BTLeafNodeKind:
		return "Leaf"
	case BTIndexNodeKind:
		return "Index"
	case BTHeaderNodeKind:
		return "Header"
	case BTMapNodeKind:
		return "Map"
	default:
		return fmt.Sprintf("Unknown(%d)", int8(kind))
	}
}

// BTNodeDescriptor is the 14-byte descriptor at the start of every node.
type BTNodeDescriptor struct {
	FLink      uint32 // next node at this level
	BLink      uint32 // previous node at this level
	Kind       BTreeNodeKind
	Height     uint8
	NumRecords uint16
	Reserved   uint16
}

// BTHeaderKeyCompareType selects the catalog key comparison algorithm.
type BTHeaderKeyCompareType uint8

const (
	HFSCaseFolding   BTHeaderKeyCompareType = 0xCF // case-insensitive (HFS+)
	HFSBinaryCompare BTHeaderKeyCompareType = 0xBC // case-sensitive (HFSX)
)

// BTHeaderRec is the first record of a B-tree header node (106 bytes).
type BTHeaderRec struct {
	TreeDepth      uint16
	RootNode       uint32
	LeafRecords    uint32
	FirstLeafNode  uint32
	LastLeafNode   uint32
	NodeSize       uint16
	MaxKeyLength   uint16
	TotalNodes     uint32
	FreeNodes      uint32
	Reserved1      uint16
	ClumpSize      uint32
	BtreeType      uint8
	KeyCompareType BTHeaderKeyCompareType
	Attributes     uint32
	Reserved3      [16]uint32
}
