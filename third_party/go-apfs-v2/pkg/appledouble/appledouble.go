// Package appledouble encodes and decodes the AppleDouble "._" sidecar
// files that carry a file's Finder info, resource fork and extended
// attributes where the file system cannot: in a cpio payload, on a
// non-Apple volume, in a zip made by Finder.
//
// The layout is the one macOS's kernel writes (xnu bsd/vfs/vfs_xattr.c)
// and pkgbuild copies into a payload, decoded from pkgbuild's output
// (testdata/cli/component-links.probe.json):
//
//	0    magic        00 05 16 07
//	4    version      00 02 00 00
//	8    filler       "Mac OS X        " (16 bytes)
//	24   numEntries   u16 = 2
//	26   entry        id 9 (Finder info), offset 50, length = attrEnd - 50
//	38   entry        id 2 (resource fork), offset attrEnd, length
//	50   Finder info  32 bytes
//	82   pad          2 bytes
//	84   ATTR header  "ATTR", debug_tag, total_size, data_start,
//	                  data_length, reserved[3], flags u16, num_attrs u16
//	120  attr entries {offset u32, length u32, flags u16, namelen u8,
//	                  name NUL} each padded to a 4-byte boundary, sorted
//	                  by name
//	data_start        values, in entry order
//	attrEnd           resource fork bytes
//
// All integers are big-endian. total_size is attrEnd: the Finder-info
// entry covers everything up to the resource fork. FromXattrs places valid
// com.apple.FinderInfo and com.apple.ResourceFork in their own slots. Noncanonical
// inputs can also contain those names in the attribute list.
package appledouble

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"path"
	"sort"
	"strings"
	"unicode/utf8"
)

// Attr is one extended attribute.
type Attr struct {
	Name  string
	Value []byte
}

// File is the content of a sidecar.
type File struct {
	FinderInfo   [32]byte
	ResourceFork []byte
	// Attrs holds wire ATTR records, including special names in noncanonical
	// inputs. Encode sorts them stably by name, retaining duplicate write order.
	Attrs []Attr
}

// Names of the attributes that have their own slots.
const (
	FinderInfoName   = "com.apple.FinderInfo"
	ResourceForkName = "com.apple.ResourceFork"
)

// Layout constants.
const (
	magic          = 0x00051607
	version        = 0x00020000
	filler         = "Mac OS X        "
	entryFinder    = 9
	entryResource  = 2
	finderOffset   = 50
	attrHeaderOff  = 84
	attrEntriesOff = 120
	attrMagic      = "ATTR"
	// MaxHeader bounds the header and attribute entry table, not the values.
	// Apple's copyfile uses ATTR_MAX_HDR_SIZE = 65536 + 18. Entry records are
	// four-byte aligned, so the largest encodable data_start is 65552.
	MaxHeader = 65536 + 18
)

var (
	// ErrNotAppleDouble reports bytes that do not start like a sidecar.
	ErrNotAppleDouble = errors.New("appledouble: not an AppleDouble file")
	// ErrTooLarge reports an attribute set the format cannot hold.
	ErrTooLarge = errors.New("appledouble: header, data offsets or lengths exceed format or address-space limits")
)

// IsSidecarName reports whether a payload or file name is an AppleDouble
// sidecar: its base name starts with "._".
func IsSidecarName(name string) bool {
	return strings.HasPrefix(path.Base(name), "._")
}

// SidecarName returns the sidecar name for a path: "./a/b" → "./a/._b".
func SidecarName(p string) string {
	dir, base := path.Split(p)
	return dir + "._" + base
}

// OwnerName returns the path a sidecar belongs to, and false if the
// name is not a sidecar's.
func OwnerName(p string) (string, bool) {
	dir, base := path.Split(p)
	if !strings.HasPrefix(base, "._") {
		return "", false
	}
	return dir + base[2:], true
}

// FromXattrs builds a File from a set of extended attributes, lifting
// Finder info and the resource fork into their slots. Invalid-length FinderInfo
// is retained verbatim in Attrs so Encode can report an error without silently
// padding or truncating the caller's value.
func FromXattrs(attrs map[string][]byte) *File {
	f := &File{}
	for name, value := range attrs {
		switch name {
		case FinderInfoName:
			if len(value) == len(f.FinderInfo) {
				copy(f.FinderInfo[:], value)
			} else {
				f.Attrs = append(f.Attrs, Attr{Name: name, Value: bytes.Clone(value)})
			}
		case ResourceForkName:
			f.ResourceFork = append([]byte(nil), value...)
		default:
			f.Attrs = append(f.Attrs, Attr{Name: name, Value: append([]byte(nil), value...)})
		}
	}
	f.sortAttrs()
	return f
}

// Xattrs returns the file's content as extended attributes, with Finder
// info and the resource fork under their names when present. For those two
// special names, ordered ATTR writes precede the dedicated slots: all-zero
// FinderInfo removes the value; resource writes overwrite a prefix without
// truncating the previous fork. Other names retain their serialized values;
// applying ACLs, quarantine and filesystem-specific policy is a separate task.
func (f *File) Xattrs() map[string][]byte {
	out := make(map[string][]byte, len(f.Attrs)+2)
	var fork []byte
	writeFork := func(value []byte) {
		if len(value) > len(fork) {
			fork = append(fork, make([]byte, len(value)-len(fork))...)
		}
		copy(fork, value)
	}
	for _, a := range f.Attrs {
		switch a.Name {
		case ResourceForkName:
			writeFork(a.Value)
		case FinderInfoName:
			if len(a.Value) == 32 && [32]byte(a.Value) == [32]byte{} {
				delete(out, a.Name)
			} else {
				out[a.Name] = a.Value
			}
		default:
			out[a.Name] = a.Value
		}
	}
	if f.FinderInfo != [32]byte{} {
		out[FinderInfoName] = append([]byte(nil), f.FinderInfo[:]...)
	}
	writeFork(f.ResourceFork)
	if len(fork) > 0 {
		out[ResourceForkName] = fork
	}
	return out
}

// Empty reports whether the file carries nothing.
func (f *File) Empty() bool {
	return f.FinderInfo == [32]byte{} && len(f.ResourceFork) == 0 && len(f.Attrs) == 0
}

func (f *File) sortAttrs() {
	sort.SliceStable(f.Attrs, func(i, j int) bool { return f.Attrs[i].Name < f.Attrs[j].Name })
}

func entrySize(name string) int {
	return (11 + len(name) + 1 + 3) &^ 3
}

// Encode writes the sidecar bytes.
func (f *File) Encode() ([]byte, error) {
	f.sortAttrs()
	entries := 0
	var valueBytes uint64
	for _, a := range f.Attrs {
		if a.Name == "" || len(a.Name) > 127 || strings.IndexByte(a.Name, 0) >= 0 || !utf8.ValidString(a.Name) {
			return nil, fmt.Errorf("appledouble: invalid attribute name %q", a.Name)
		}
		if err := validateFinderInfo(a.Name, uint64(len(a.Value))); err != nil {
			return nil, err
		}
		if entrySize(a.Name) > MaxHeader-attrEntriesOff-entries {
			return nil, ErrTooLarge
		}
		entries += entrySize(a.Name)
		valueBytes += uint64(len(a.Value))
		if valueBytes > math.MaxUint32 {
			return nil, ErrTooLarge
		}
	}
	dataStart := attrEntriesOff + entries
	bufferSize, err := encodedSize(uint64(dataStart), valueBytes, uint64(len(f.ResourceFork)))
	if err != nil {
		return nil, err
	}
	values := int(valueBytes)
	attrEnd := dataStart + values

	var b bytes.Buffer
	b.Grow(bufferSize)
	_ = binary.Write(&b, binary.BigEndian, uint32(magic))
	_ = binary.Write(&b, binary.BigEndian, uint32(version))
	b.WriteString(filler)
	_ = binary.Write(&b, binary.BigEndian, uint16(2))
	_ = binary.Write(&b, binary.BigEndian, uint32(entryFinder))
	_ = binary.Write(&b, binary.BigEndian, uint32(finderOffset))
	_ = binary.Write(&b, binary.BigEndian, uint32(attrEnd-finderOffset))
	_ = binary.Write(&b, binary.BigEndian, uint32(entryResource))
	_ = binary.Write(&b, binary.BigEndian, uint32(attrEnd))
	_ = binary.Write(&b, binary.BigEndian, uint32(len(f.ResourceFork)))
	b.Write(f.FinderInfo[:])
	b.Write([]byte{0, 0})
	b.WriteString(attrMagic)
	_ = binary.Write(&b, binary.BigEndian, uint32(0)) // debug_tag
	_ = binary.Write(&b, binary.BigEndian, uint32(attrEnd))
	_ = binary.Write(&b, binary.BigEndian, uint32(dataStart))
	_ = binary.Write(&b, binary.BigEndian, uint32(values))
	b.Write(make([]byte, 12)) // reserved
	_ = binary.Write(&b, binary.BigEndian, uint16(0))
	_ = binary.Write(&b, binary.BigEndian, uint16(len(f.Attrs)))
	off := dataStart
	for _, a := range f.Attrs {
		valueOffset := off
		// copyfile leaves the zero-initialized offset for an empty value.
		// Presence is represented by the named entry, not by a data pointer.
		if len(a.Value) == 0 {
			valueOffset = 0
		}
		_ = binary.Write(&b, binary.BigEndian, uint32(valueOffset))
		_ = binary.Write(&b, binary.BigEndian, uint32(len(a.Value)))
		_ = binary.Write(&b, binary.BigEndian, uint16(0))
		b.WriteByte(byte(len(a.Name) + 1))
		b.WriteString(a.Name)
		b.WriteByte(0)
		for b.Len()%4 != 0 {
			b.WriteByte(0)
		}
		off += len(a.Value)
	}
	for _, a := range f.Attrs {
		b.Write(a.Value)
	}
	b.Write(f.ResourceFork)
	return b.Bytes(), nil
}

// Validate wire widths and address space before converting sizes or allocating.
// Values may extend beyond the header buffer; the fork has its own uint32 length.
func encodedSize(header, values, fork uint64) (int, error) {
	if header > MaxHeader || values > math.MaxUint32-header || fork > math.MaxUint32 {
		return 0, ErrTooLarge
	}
	total := header + values + fork
	if total > uint64(math.MaxInt) {
		return 0, ErrTooLarge
	}
	return int(total), nil
}

// Sniff reports whether b starts with the AppleDouble magic and version.
func Sniff(b []byte) bool {
	return len(b) >= 8 && binary.BigEndian.Uint32(b) == magic && binary.BigEndian.Uint32(b[4:]) == version
}

// Decode parses the macOS AppleDouble profile used by copyfile. The first
// entry describes FinderInfo and the optional ATTR records; only a resource
// fork in the second entry is consumed. Summary sizes do not bound value reads:
// each actual read is checked against the input, with a cumulative copy budget.
func Decode(b []byte) (*File, error) {
	if !Sniff(b) || len(b) < 82 || binary.BigEndian.Uint16(b[24:]) != 2 || binary.BigEndian.Uint32(b[26:]) != entryFinder {
		return nil, ErrNotAppleDouble
	}
	// copyfile reads only this much into its header buffer. Attribute values
	// and the resource fork are read separately from their file offsets.
	header := bytes.Clone(b[:min(len(b), MaxHeader)])
	for _, off := range []int{0, 4, 26, 30, 34, 38, 42, 46} {
		native32(header, off)
	}
	native16(header, 24)
	f := &File{}
	// Canonical files store each payload once. Bound retained payload copies
	// even if many records alias the same bytes; this deliberately rejects
	// some inputs native copyfile can process sequentially without retaining.
	copyBudget := len(b)
	readValue := func(offset, length uint32) ([]byte, error) {
		// Native pread of zero bytes succeeds even beyond EOF. Avoid converting
		// the unused offset to int, which could wrap on 386.
		if length == 0 {
			return nil, nil
		}
		if uint64(offset)+uint64(length) > uint64(len(b)) {
			return nil, fmt.Errorf("appledouble: value (offset %d, length %d) outside the file", offset, length)
		}
		if uint64(length) > uint64(copyBudget) {
			return nil, fmt.Errorf("appledouble: copied data exceeds the file size")
		}
		copyBudget -= int(length)
		return bytes.Clone(b[int(offset) : int(offset)+int(length)]), nil
	}
	finderLength := binary.BigEndian.Uint32(b[34:])
	if finderLength > 32 {
		if len(header) < attrEntriesOff || string(b[attrHeaderOff:attrHeaderOff+4]) != attrMagic {
			return nil, fmt.Errorf("appledouble: missing or truncated ATTR header")
		}
		for _, off := range []int{84, 88, 92, 96, 100} {
			native32(header, off)
		}
		native16(header, 116)
		native16(header, 118)
		numAttrs := int(binary.BigEndian.Uint16(b[118:]))
		off := attrEntriesOff
		for i := 0; i < numAttrs; i++ {
			if !containsRange(len(header), off, 12) {
				return nil, fmt.Errorf("appledouble: truncated attribute entry %d", i)
			}
			native32(header, off)
			native32(header, off+4)
			native16(header, off+8)
			nameLen := int(header[off+10])
			if nameLen < 2 || nameLen > 128 || nameLen > len(header)-off-11 {
				return nil, fmt.Errorf("appledouble: bad name length in attribute entry %d", i)
			}
			nameBytes := header[off+11 : off+11+nameLen]
			if nameBytes[nameLen-1] != 0 {
				return nil, fmt.Errorf("appledouble: unterminated name in attribute entry %d", i)
			}
			nameBytes = nameBytes[:bytes.IndexByte(nameBytes, 0)]
			if len(nameBytes) == 0 || !utf8.Valid(nameBytes) {
				return nil, fmt.Errorf("appledouble: invalid name in attribute entry %d", i)
			}
			if err := validateFinderInfo(string(nameBytes), uint64(binary.BigEndian.Uint32(b[off+4:]))); err != nil {
				return nil, err
			}
			value, err := readValue(binary.BigEndian.Uint32(b[off:]), binary.BigEndian.Uint32(b[off+4:]))
			if err != nil {
				return nil, err
			}
			f.Attrs = append(f.Attrs, Attr{Name: string(nameBytes), Value: value})
			off += (11 + nameLen + 3) &^ 3
		}
	}
	finderOffset := binary.BigEndian.Uint32(b[30:])
	if uint64(finderOffset)+32 > uint64(len(header)) {
		return nil, fmt.Errorf("appledouble: FinderInfo outside the native header buffer")
	}
	// Native copyfile reads FinderInfo from its endian-converted header buffer,
	// not from the file. This also defines overlapping-header behavior. Both
	// supported Mac architectures are little-endian; emulate that on every host.
	copy(f.FinderInfo[:], header[int(finderOffset):int(finderOffset)+32])
	if binary.BigEndian.Uint32(b[38:]) == entryResource {
		var err error
		f.ResourceFork, err = readValue(binary.BigEndian.Uint32(b[42:]), binary.BigEndian.Uint32(b[46:]))
		if err != nil {
			return nil, err
		}
	}
	return f, nil
}

func validateFinderInfo(name string, length uint64) error {
	if name == FinderInfoName && length != 32 {
		return fmt.Errorf("appledouble: FinderInfo requires exactly 32 bytes, got %d", length)
	}
	return nil
}

func native32(b []byte, off int) {
	binary.LittleEndian.PutUint32(b[off:], binary.BigEndian.Uint32(b[off:]))
}
func native16(b []byte, off int) {
	binary.LittleEndian.PutUint16(b[off:], binary.BigEndian.Uint16(b[off:]))
}

// Subtraction-based bounds avoid overflowing int before a slice check on 386.
func containsRange(size, offset, length int) bool {
	return offset >= 0 && length >= 0 && offset <= size && length <= size-offset
}
