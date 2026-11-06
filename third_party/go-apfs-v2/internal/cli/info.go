// apfs info IMAGE — container and volume summary.
package cli

import (
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/tools"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfsversion"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/spf13/cobra"
)

var (
	infoHierarchy bool
	infoBodyfile  string
	infoMD5       bool
	infoEntryID   uint64
	infoFilePath  string
)

var infoCmd = &cobra.Command{
	Use:   "info IMAGE",
	Short: "Display container and volume information",
	Long: `Display information about the file system in an image and each of its
volumes. The file system (APFS or HFS+) is detected automatically; the JSON
output includes a "fileSystem" field ("apfs" or "hfs+"), the container and
per-volume UUIDs, sizes, and file/directory/symlink counts.

Legacy forensic flags (--hierarchy, --bodyfile, --md5, --entry, --file-path)
produce the detailed fsapfsinfo-style text report and are APFS-only,
text-only.

Examples:
  apfs info image.dmg
  apfs info -o json image.dmg | jq '.volumes[0].name'
  apfs info -o json image.dmg | jq -r .fileSystem
  apfs info -v "Macintosh HD" image.dmg     # select a volume by name or UUID
  apfs info --hierarchy image.dmg           # full tree (APFS, text)
  apfs info --bodyfile out.body image.dmg   # Sleuth Kit bodyfile`,
	Args: exactArgs(1, "IMAGE"),
	RunE: runInfo,
}

func init() {
	infoCmd.Flags().BoolVar(&infoHierarchy, "hierarchy", false, "print the full file system hierarchy (text only)")
	infoCmd.Flags().StringVar(&infoBodyfile, "bodyfile", "", "write a Sleuth Kit bodyfile to this path (text only)")
	infoCmd.Flags().BoolVar(&infoMD5, "md5", false, "calculate MD5 hashes in the bodyfile (text only)")
	infoCmd.Flags().Uint64Var(&infoEntryID, "entry", 0, "show the file entry with this identifier (text only)")
	infoCmd.Flags().StringVar(&infoFilePath, "file-path", "", "show the file entry at this volume path (text only)")
}

// containerInfo is the JSON schema for apfs info.
type containerInfo struct {
	FileSystem  string `json:"fileSystem"` // "apfs" or "hfs+"
	UUID        string `json:"uuid"`
	Size        uint64 `json:"size"`
	BlockSize   uint32 `json:"blockSize"`
	VolumeCount int    `json:"volumeCount"`
	Locked      bool   `json:"locked"`
	// NewestMountedVersion is the newest Apple APFS driver build that mounted
	// the container (nx_newest_mounted_version), omitted when never recorded.
	NewestMountedVersion string       `json:"newestMountedVersion,omitempty"`
	Volumes              []volumeInfo `json:"volumes"`
}

type volumeInfo struct {
	Index         int    `json:"index"`
	Name          string `json:"name"`
	UUID          string `json:"uuid"`
	CaseSensitive bool   `json:"caseSensitive"`
	// Encrypted says the volume's contents are stored enciphered (FileVault);
	// Locked says they could not be deciphered, because no password was given
	// or the one given did not fit. An unlocked encrypted volume is readable
	// and still worth naming as encrypted.
	Encrypted bool `json:"encrypted"`
	Locked    bool `json:"locked"`
	// Role is the lowercase role token ("system", "data", …), omitted when the
	// volume has no role; RoleValue is the raw apfs_role, always present so a
	// consumer can see a value this build does not recognize. VolumeGroupID is
	// the volume group UUID, omitted when the volume is in no group.
	Role          string    `json:"role,omitempty"`
	RoleName      string    `json:"roleName,omitempty"`
	RoleValue     uint16    `json:"roleValue"`
	VolumeGroupID string    `json:"volumeGroupId,omitempty"`
	Files         uint64    `json:"files"`
	Directories   uint64    `json:"directories"`
	Symlinks      uint64    `json:"symlinks"`
	Snapshots     uint64    `json:"snapshots"`
	Size          uint64    `json:"size"`
	UnmountTime   time.Time `json:"unmountTime"`
	// FormattedBy and LastModifiedBy are the writer stamps Apple's tools leave
	// in the volume superblock ("newfs_apfs (3288.1.3)"); FormatterMacOS names
	// the macOS release that build series shipped in when it is in the ledger.
	FormattedBy    string `json:"formattedBy,omitempty"`
	LastModifiedBy string `json:"lastModifiedBy,omitempty"`
	FormatterMacOS string `json:"formatterMacOS,omitempty"`
}

func runInfo(cmd *cobra.Command, args []string) error {
	imagePath := args[0]

	// Legacy detailed report path (fsapfsinfo port, APFS only)
	if infoHierarchy || infoBodyfile != "" || infoEntryID != 0 || infoFilePath != "" {
		return runLegacyInfo(imagePath)
	}

	if _, err := os.Stat(imagePath); err != nil {
		return withCode(ExitBadImage, fmt.Errorf("unable to open image: %w", err))
	}

	reader, sniffedOffset, closer, err := disk.OpenWithOffset(imagePath)
	if err != nil {
		return withCode(ExitBadImage, fmt.Errorf("unable to open image: %w", err))
	}
	defer closer.Close()

	offset := opts.Offset
	if offset == 0 {
		offset = sniffedOffset
	}
	base := io.ReaderAt(reader)
	if offset != 0 {
		base = io.NewSectionReader(reader, offset, math.MaxInt64-offset)
	}

	var info *containerInfo

	switch sniffFileSystem(base) {
	case "apfs":
		container, err := apfs.Open(base, &apfs.OpenOptions{
			Password:         opts.Password,
			RecoveryPassword: opts.RecoveryPassword,
		})
		if err != nil {
			return withCode(ExitBadImage, fmt.Errorf("unable to open APFS container: %w", err))
		}
		defer container.Close()
		info, err = collectContainerInfo(container)
		if err == nil {
			if newest, e := apfsversion.ReadNewestMounted(imagePath); e == nil && !newest.IsZero() {
				info.NewestMountedVersion = newest.String()
			}
		}
		if err != nil {
			return err
		}

	case "hfsplus":
		volume, err := hfsplus.New(base)
		if err != nil {
			return withCode(ExitBadImage, fmt.Errorf("unable to open HFS+ volume: %w", err))
		}
		info = collectHFSInfo(volume)

	default:
		return withCode(ExitBadImage, fmt.Errorf("%s does not contain a recognizable APFS or HFS+ file system", imagePath))
	}

	if opts.Output == "json" {
		return jsonOut(info)
	}

	printContainerInfo(info)
	return nil
}

// collectHFSInfo builds the info schema for an HFS+ volume. File, directory
// and symlink counts are taken from a walk of the visible tree (the volume
// header's own counters include hidden housekeeping entries).
func collectHFSInfo(volume *hfsplus.Volume) *containerInfo {
	header := volume.Header()

	var files, dirs, symlinks uint64
	// The callback skips unreadable entries, so the walk itself never fails.
	_ = fs.WalkDir(volume, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || name == "." {
			return nil
		}
		switch {
		case entry.IsDir():
			dirs++
		case entry.Type()&fs.ModeSymlink != 0:
			symlinks++
		default:
			files++
		}
		return nil
	})

	uuid := strings.ToLower(volume.UUID())

	return &containerInfo{
		FileSystem:  "hfs+",
		UUID:        uuid,
		Size:        uint64(header.TotalBlocks) * uint64(header.BlockSize),
		BlockSize:   header.BlockSize,
		VolumeCount: 1,
		Volumes: []volumeInfo{{
			Index:         0,
			Name:          volume.Name(),
			UUID:          uuid,
			CaseSensitive: volume.CaseSensitive(),
			Files:         files,
			Directories:   dirs,
			Symlinks:      symlinks,
			Size:          uint64(header.TotalBlocks-header.FreeBlocks) * uint64(header.BlockSize),
			UnmountTime:   volume.Modified().UTC(),
		}},
	}
}

func collectContainerInfo(container *apfs.Container) (*containerInfo, error) { //nolint:unparam
	uuid, err := container.Identifier()
	if err != nil {
		return nil, fmt.Errorf("unable to get container identifier: %w", err)
	}

	size, err := container.Size()
	if err != nil {
		return nil, fmt.Errorf("unable to get container size: %w", err)
	}

	locked, _ := container.IsLocked()

	volumes, err := container.Volumes()
	if err != nil {
		return nil, fmt.Errorf("unable to enumerate volumes: %w", err)
	}

	info := &containerInfo{
		FileSystem:  "apfs",
		UUID:        formatUUIDBytes(uuid),
		Size:        size,
		BlockSize:   container.IOHandle.BlockSize,
		VolumeCount: len(volumes),
		Locked:      locked,
	}

	for index, volume := range volumes {
		vi := volumeInfo{Index: index}

		if name, err := volume.UTF8Name(); err == nil {
			vi.Name = name
		}
		if volUUID, err := volume.Identifier(); err == nil {
			vi.UUID = formatUUIDBytes(volUUID[:])
		}
		if volume.Superblock != nil {
			vi.FormattedBy = stampString(volume.Superblock.FormattedBy.ID)
			vi.LastModifiedBy = stampString(volume.Superblock.ModifiedBy[0].ID)
			vi.FormatterMacOS = formatterMacOS(vi.FormattedBy, vi.LastModifiedBy)
		}
		if ci, err := volume.IsCaseInsensitive(); err == nil {
			vi.CaseSensitive = !ci
		}
		if volEncrypted, err := volume.IsEncrypted(); err == nil {
			vi.Encrypted = volEncrypted
		}
		if volLocked, err := volume.IsLocked(); err == nil {
			vi.Locked = volLocked
		}
		if role, err := volume.Role(); err == nil {
			vi.RoleValue = role
			vi.Role = apfs.VolumeRoleString(role)
			vi.RoleName = apfs.VolumeRoleName(role)
		}
		if groupID, err := volume.VolumeGroupIdentifier(); err == nil && groupID != ([16]byte{}) {
			vi.VolumeGroupID = formatUUIDBytes(groupID[:])
		}

		if sb := volume.Superblock; sb != nil {
			vi.Files = sb.NumberOfFiles
			vi.Directories = sb.NumberOfDirectories
			vi.Symlinks = sb.NumberOfSymlinks
			vi.Snapshots = sb.SnapshotCount
			vi.Size = sb.TotalBlocksAllocated * uint64(container.IOHandle.BlockSize)
			if sb.UnmountTime != 0 {
				vi.UnmountTime = time.Unix(0, int64(sb.UnmountTime)).UTC()
			}
		}

		info.Volumes = append(info.Volumes, vi)
	}

	return info, nil
}

func printContainerInfo(info *containerInfo) {
	switch info.FileSystem {
	case "hfs+":
		fmt.Println("HFS+ volume:")
	default:
		fmt.Println("Apple File System (APFS) container:")
	}
	fmt.Println()
	fmt.Printf("  %-18s %s\n", "UUID", info.UUID)
	fmt.Printf("  %-18s %s (%d bytes)\n", "Size", formatSize(info.Size), info.Size)
	fmt.Printf("  %-18s %d bytes\n", "Block size", info.BlockSize)
	fmt.Printf("  %-18s %d\n", "Volumes", info.VolumeCount)
	if info.NewestMountedVersion != "" {
		fmt.Printf("  %-18s APFS %s\n", "Newest mounted by", info.NewestMountedVersion)
	}
	if info.Locked {
		fmt.Printf("  %-18s yes\n", "Locked")
	}

	for _, vi := range info.Volumes {
		fmt.Println()
		fmt.Printf("Volume %d: %s\n", vi.Index, vi.Name)
		fmt.Printf("  %-18s %s\n", "UUID", vi.UUID)
		if vi.RoleName != "" {
			fmt.Printf("  %-18s %s\n", "Role", vi.RoleName)
		}
		if vi.VolumeGroupID != "" {
			fmt.Printf("  %-18s %s\n", "Volume group", vi.VolumeGroupID)
		}
		fmt.Printf("  %-18s %s (%d bytes)\n", "Size", formatSize(vi.Size), vi.Size)
		fmt.Printf("  %-18s %d files, %d directories, %d symlinks\n", "Contents", vi.Files, vi.Directories, vi.Symlinks)
		if vi.Snapshots > 0 {
			fmt.Printf("  %-18s %d\n", "Snapshots", vi.Snapshots)
		}
		fmt.Printf("  %-18s %v\n", "Case-sensitive", vi.CaseSensitive)
		if vi.FormattedBy != "" {
			fmt.Printf("  %-18s %s\n", "Formatted by", vi.FormattedBy)
		}
		if vi.LastModifiedBy != "" {
			fmt.Printf("  %-18s %s\n", "Last modified by", vi.LastModifiedBy)
		}
		if vi.FormatterMacOS != "" {
			fmt.Printf("  %-18s %s\n", "APFS release", vi.FormatterMacOS)
		}
		if vi.Encrypted {
			fmt.Printf("  %-18s yes\n", "Encrypted")
		}
		if vi.Locked {
			fmt.Printf("  %-18s yes\n", "Locked")
		}
		if !vi.UnmountTime.IsZero() {
			fmt.Printf("  %-18s %s\n", "Unmount time", vi.UnmountTime.Format(time.RFC3339))
		}
	}
}

func formatUUIDBytes(uuid []byte) string {
	if len(uuid) != 16 {
		return fmt.Sprintf("%x", uuid)
	}
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid[0], uuid[1], uuid[2], uuid[3],
		uuid[4], uuid[5],
		uuid[6], uuid[7],
		uuid[8], uuid[9],
		uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15])
}

// runLegacyInfo produces the detailed fsapfsinfo-style report through the
// ported InfoHandle (text only).
func runLegacyInfo(imagePath string) error {
	if opts.Output == "json" {
		return usageErrorf("--hierarchy/--bodyfile/--entry/--file-path produce text output only")
	}

	handle, err := tools.NewInfoHandle(infoMD5)
	if err != nil {
		return err
	}
	handle.NotifyStream = os.Stdout

	if opts.Volume != "" {
		if err := handle.SetVolumeIndex(opts.Volume); err != nil {
			return usageErrorf("legacy info flags select volumes by index: %v", err)
		}
	}
	if opts.Offset != 0 {
		handle.VolumeOffset = opts.Offset
	}
	if opts.Password != "" {
		if err := handle.SetPassword(opts.Password); err != nil {
			return err
		}
	}
	if opts.RecoveryPassword != "" {
		if err := handle.SetRecoveryPassword(opts.RecoveryPassword); err != nil {
			return err
		}
	}
	if infoBodyfile != "" {
		if err := handle.SetBodyfile(infoBodyfile); err != nil {
			return err
		}
	}

	if err := handle.OpenInput(imagePath); err != nil {
		return withCode(ExitBadImage, err)
	}
	defer func() { _ = handle.CloseInput() }()

	switch {
	case infoEntryID != 0:
		return handle.PrintFileEntryByIdentifier(infoEntryID)
	case infoFilePath != "":
		return handle.PrintFileEntryByPath(infoFilePath)
	case infoBodyfile != "":
		return handle.PrintFileEntries()
	default:
		return handle.PrintFileSystemHierarchy()
	}
}

// stampString renders an on-disk apfs_modified_by identifier without padding.
func stampString(id [32]byte) string {
	return strings.TrimRight(string(id[:]), "\x00")
}

// formatterMacOS attributes the newest Apple build among the stamps to a macOS
// release from the apfsversion ledger, or returns "" for non-Apple writers.
func formatterMacOS(stamps ...string) string {
	var newest apfsversion.Version
	for _, raw := range stamps {
		if st, err := apfsversion.ParseStamp(raw); err == nil && st.IsApple() && (newest.IsZero() || st.Version.Compare(newest) > 0) {
			newest = st.Version
		}
	}
	if newest.IsZero() {
		return ""
	}
	if r, ok := apfsversion.ReleaseForSeries(newest.Series()); ok {
		return fmt.Sprintf("%d (%s)", newest.Series(), r.MacOS)
	}
	if major, _, ok := apfsversion.MacOSMajor(newest.Series()); ok {
		return fmt.Sprintf("%d (macOS %d, inferred)", newest.Series(), major)
	}
	return fmt.Sprintf("%d (not in ledger)", newest.Series())
}
