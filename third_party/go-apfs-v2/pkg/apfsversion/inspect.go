package apfsversion

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/deploymenttheory/go-apfs-v2/internal/nameunicode"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

// VolumeInspection is what the portable reader found in one volume.
type VolumeInspection struct {
	Name           string
	FormattedBy    Stamp
	LastModifiedBy Stamp
	// Entries is the number of directory entries walked.
	Entries int
	// UnrepresentableNames counts stored names the inspected host's kernel
	// refuses to create (EILSEQ). Zero when NamesInspected is false.
	UnrepresentableNames int
	// Samples holds up to SampleLimit quoted unrepresentable names.
	Samples []string
}

// Inspection is the result of Inspect for one image.
type Inspection struct {
	// NewestMounted is nx_newest_mounted_version from the container
	// superblock at block 0, or empty when the container never recorded one.
	NewestMounted Version
	// HostMajor is the macOS major whose admission tables were applied, or 0
	// when names were not inspected.
	HostMajor int
	Volumes   []VolumeInspection
}

// SampleLimit bounds the quoted names retained per volume.
const SampleLimit = 8

// Image converts one inspected volume into the Image that AssessNativeMount
// takes. Names count as inspected when Inspect was given a host major.
func (i Inspection) Image(volume int) Image {
	v := i.Volumes[volume]
	return Image{FormattedBy: v.FormattedBy, LastModifiedBy: v.LastModifiedBy, NewestMounted: i.NewestMounted, UnrepresentableNames: v.UnrepresentableNames, NamesInspected: i.HostMajor != 0}
}

// nxNewestMountedVersionOffset is the byte offset of nx_newest_mounted_version
// within nx_superblock_t. The field follows nx_fusion_wbc (a prange) and
// precedes nx_mkb_locker; it is absent from the 2020 reference.
const nxNewestMountedVersionOffset = 1384

// ReadNewestMounted reads nx_newest_mounted_version from the container
// superblock at block 0 of the image, which macOS rewrites on every clean
// unmount. Images produced by go-apfs leave it zero, which reads as empty.
func ReadNewestMounted(path string) (Version, error) {
	reader, offset, closer, err := disk.OpenWithOffset(path)
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	return readNewestMounted(reader, offset)
}

func readNewestMounted(reader io.ReaderAt, offset int64) (Version, error) {
	var buf [8]byte
	if _, err := reader.ReadAt(buf[:], offset+nxNewestMountedVersionOffset); err != nil {
		return nil, fmt.Errorf("apfsversion: nx_newest_mounted_version: %w", err)
	}
	return DecodePacked(binary.LittleEndian.Uint64(buf[:])), nil
}

// ErrHostMajor reports a host major release without admission tables.
var ErrHostMajor = errors.New("apfsversion: no filename admission table for that macOS release")

// Inspect reads an image's version stamps with the portable reader and, when
// hostMajor is 15, 26 or 27, walks every directory and counts stored names that
// release's kernel cannot represent. hostMajor 0 skips the walk. The image is
// never mounted.
func Inspect(path string, hostMajor int) (Inspection, error) {
	if hostMajor != 0 {
		if _, err := osversion.ProfileForMacOS(osversion.Version{Major: uint32(hostMajor)}); err != nil {
			return Inspection{}, fmt.Errorf("%w: %d", ErrHostMajor, hostMajor)
		}
	}
	newest, err := ReadNewestMounted(path)
	if err != nil {
		return Inspection{}, err
	}
	container, closer, err := apfs.OpenImage(path, nil)
	if err != nil {
		return Inspection{}, err
	}
	defer closer.Close()
	volumes, err := container.Volumes()
	if err != nil {
		return Inspection{}, err
	}
	result := Inspection{NewestMounted: newest, HostMajor: hostMajor}
	for index, volume := range volumes {
		vi, err := inspectVolume(volume, hostMajor)
		if err != nil {
			return Inspection{}, fmt.Errorf("volume %d: %w", index, err)
		}
		result.Volumes = append(result.Volumes, vi)
	}
	return result, nil
}

func inspectVolume(volume *apfs.Volume, hostMajor int) (VolumeInspection, error) {
	if volume.Superblock == nil {
		return VolumeInspection{}, errors.New("apfsversion: volume superblock not loaded")
	}
	vi := VolumeInspection{}
	if name, err := volume.UTF8Name(); err == nil {
		vi.Name = name
	}
	stamp := func(b [32]byte) Stamp {
		s, err := ParseStamp(strings.TrimRight(string(b[:]), "\x00"))
		if err != nil {
			return Stamp{Tool: strings.TrimRight(string(b[:]), "\x00")}
		}
		return s
	}
	vi.FormattedBy = stamp(volume.Superblock.FormattedBy.ID)
	vi.LastModifiedBy = stamp(volume.Superblock.ModifiedBy[0].ID)
	if hostMajor == 0 {
		return vi, nil
	}
	root, err := volume.RootDirectory()
	if err != nil {
		return vi, err
	}
	err = walk(root, func(name []byte) {
		vi.Entries++
		if representable(name, hostMajor) {
			return
		}
		vi.UnrepresentableNames++
		if len(vi.Samples) < SampleLimit {
			vi.Samples = append(vi.Samples, fmt.Sprintf("%+q", name))
		}
	})
	return vi, err
}

// representable reports whether the kernel of macOS hostMajor admits the
// stored name: valid UTF-8 whose every scalar that release's APFS accepts at
// creation. Invalid UTF-8 can only have been stored by a foreign writer.
func representable(name []byte, hostMajor int) bool {
	if !utf8.Valid(name) {
		return false
	}
	for _, r := range string(name) {
		if !nameunicode.APFSCreateAllowed(r, hostMajor) {
			return false
		}
	}
	return true
}

const directoryMode = 0o040000

func walk(dir *apfs.FileEntry, visit func(name []byte)) error {
	count, err := dir.NumberOfSubFileEntries()
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		child, err := dir.SubFileEntryByIndex(i)
		if err != nil {
			return err
		}
		if child.DirectoryEntryRecord != nil {
			visit(child.DirectoryEntryRecord.Name)
		}
		mode, err := child.FileMode()
		if err != nil {
			return err
		}
		if mode&0o170000 == directoryMode {
			if err := walk(child, visit); err != nil {
				return err
			}
		}
	}
	return nil
}
