// Info handle for displaying APFS container and volume information
package tools

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

// formatUUID formats a 16-byte UUID as a string in standard format
// e.g., "550e8400-e29b-41d4-a716-446655440000"
func formatUUID(uuid []byte) string {
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

// formatUUIDArray formats a 16-byte UUID array as a string in standard format
func formatUUIDArray(uuid [16]byte) string {
	return formatUUID(uuid[:])
}

// formatBytes converts bytes to human-readable format
func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	return fmt.Sprintf("%.1f %s", float64(bytes)/float64(div), units[exp])
}

// formatNumber formats a number with comma separators
func formatNumber(n uint64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var result []byte
	for i, digit := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, digit)
	}
	return string(result)
}

// repeatChar repeats a character n times
func repeatChar(char rune, n int) string {
	if n <= 0 {
		return ""
	}
	result := make([]rune, n)
	for i := range result {
		result[i] = char
	}
	return string(result)
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// InfoHandle provides functionality for displaying APFS information
type InfoHandle struct {
	// VolumeIndex specifies which volume to show (or -1 for all)
	VolumeIndex int

	// RecoveryPassword for encrypted volumes
	RecoveryPassword string

	// UserPassword for encrypted volumes
	UserPassword string

	// VolumeOffset specifies the byte offset of the volume
	VolumeOffset int64

	// InputContainer holds the opened APFS container
	InputContainer *apfs.Container

	// ContainerIsLocked indicates if the container is encrypted and locked
	ContainerIsLocked bool

	// CalculateMD5 indicates if MD5 hashes should be calculated for files
	CalculateMD5 bool

	// BodyfileStream is the output stream for bodyfile format
	BodyfileStream io.Writer

	// NotifyStream is the stream for notifications and information output
	NotifyStream io.Writer

	// Abort flag for signal handling
	Abort bool

	// inputCloser closes the underlying image reader on CloseInput
	inputCloser io.Closer
}

// NewInfoHandle creates a new info handle
func NewInfoHandle(calculateMD5 bool) (*InfoHandle, error) {
	return &InfoHandle{
		VolumeIndex:       -1, // -1 means all volumes
		VolumeOffset:      0,
		CalculateMD5:      calculateMD5,
		NotifyStream:      os.Stdout,
		ContainerIsLocked: false,
		Abort:             false,
	}, nil
}

// SetBodyfile sets the bodyfile output stream
func (ih *InfoHandle) SetBodyfile(filename string) error {
	if filename == "" {
		return fmt.Errorf("invalid filename")
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("unable to create bodyfile: %w", err)
	}

	ih.BodyfileStream = file
	return nil
}

// SetVolumeIndex sets the volume index from a string
func (ih *InfoHandle) SetVolumeIndex(indexStr string) error {
	if indexStr == "all" {
		ih.VolumeIndex = -1
		return nil
	}

	index, err := strconv.Atoi(indexStr)
	if err != nil {
		return fmt.Errorf("invalid file system index: %w", err)
	}

	if index < 0 {
		return fmt.Errorf("invalid file system index: must be non-negative")
	}

	ih.VolumeIndex = index
	return nil
}

// SetPassword sets the user password
func (ih *InfoHandle) SetPassword(password string) error {
	if password == "" {
		return fmt.Errorf("invalid password")
	}

	ih.UserPassword = password
	return nil
}

// SetRecoveryPassword sets the recovery password
func (ih *InfoHandle) SetRecoveryPassword(password string) error {
	if password == "" {
		return fmt.Errorf("invalid recovery password")
	}

	ih.RecoveryPassword = password
	return nil
}

// SetVolumeOffset sets the volume offset from a string
func (ih *InfoHandle) SetVolumeOffset(offsetStr string) error {
	offset, err := strconv.ParseInt(offsetStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid volume offset: %w", err)
	}

	if offset < 0 {
		return fmt.Errorf("invalid volume offset: must be non-negative")
	}

	ih.VolumeOffset = offset
	return nil
}

// OpenInput opens the APFS container from a file
func (ih *InfoHandle) OpenInput(filename string) error {
	if filename == "" {
		return fmt.Errorf("invalid filename")
	}

	// Open the image with content-based format detection (DMG, GPT raw
	// image, or bare container)
	reader, sniffedOffset, closer, err := disk.OpenWithOffset(filename)
	if err != nil {
		return fmt.Errorf("unable to open file: %w", err)
	}

	// An explicit --offset always wins over the sniffed partition offset
	offset := ih.VolumeOffset
	if offset == 0 {
		offset = sniffedOffset
	}

	// Create IO handle
	ioHandle, err := apfs.NewIOHandle()
	if err != nil {
		closer.Close()
		return fmt.Errorf("unable to create IO handle: %w", err)
	}

	// Create container
	container, err := apfs.NewContainer(ioHandle)
	if err != nil {
		closer.Close()
		return fmt.Errorf("unable to create container: %w", err)
	}

	// Open container for reading
	if err := container.OpenRead(reader, offset); err != nil {
		closer.Close()
		return fmt.Errorf("unable to open container: %w", err)
	}

	ih.InputContainer = container
	ih.inputCloser = closer

	// Check if container is locked
	isLocked, err := container.IsLocked()
	if err != nil {
		return fmt.Errorf("unable to determine if container is locked: %w", err)
	}
	ih.ContainerIsLocked = isLocked

	// If we have passwords, set them on all volumes for later unlocking
	// Note: Passwords need to be set per-volume, not at container level
	if ih.UserPassword != "" || ih.RecoveryPassword != "" {
		numberOfVolumes, err := container.NumberOfVolumes()
		if err != nil {
			return fmt.Errorf("unable to get number of volumes: %w", err)
		}

		for i := 0; i < numberOfVolumes; i++ {
			volume, err := container.Volume(i)
			if err != nil {
				continue // Skip volumes that can't be retrieved
			}

			// Set user password if provided
			if ih.UserPassword != "" {
				if err := volume.SetUTF8Password([]byte(ih.UserPassword)); err != nil {
					// Non-fatal: continue even if password setting fails
					if ih.NotifyStream != nil {
						fmt.Fprintf(ih.NotifyStream, "Warning: failed to set password for volume %d: %v\n", i, err)
					}
				}
			}

			// Set recovery password if provided
			if ih.RecoveryPassword != "" {
				if err := volume.SetUTF8RecoveryPassword([]byte(ih.RecoveryPassword)); err != nil {
					// Non-fatal: continue even if password setting fails
					if ih.NotifyStream != nil {
						fmt.Fprintf(ih.NotifyStream, "Warning: failed to set recovery password for volume %d: %v\n", i, err)
					}
				}
			}

			// Attempt to unlock the volume
			unlocked, err := volume.Unlock()
			if err != nil {
				// Non-fatal: volume may not be encrypted or may have wrong password
				if ih.NotifyStream != nil {
					fmt.Fprintf(ih.NotifyStream, "Warning: failed to unlock volume %d: %v\n", i, err)
				}
			} else if unlocked {
				if ih.NotifyStream != nil {
					fmt.Fprintf(ih.NotifyStream, "Volume %d unlocked successfully\n", i)
				}
			}
		}
	}

	return nil
}

// CloseInput closes the input container
func (ih *InfoHandle) CloseInput() error {
	if ih.InputContainer == nil {
		return fmt.Errorf("invalid info handle - input container not set")
	}

	// Free container resources
	if err := ih.InputContainer.Close(); err != nil {
		return fmt.Errorf("unable to free container: %w", err)
	}

	ih.InputContainer = nil

	if ih.inputCloser != nil {
		ih.inputCloser.Close()
		ih.inputCloser = nil
	}

	return nil
}

// VolumeByIndex retrieves a volume by its index
func (ih *InfoHandle) VolumeByIndex(volumeIndex int) (*apfs.Volume, error) {
	if ih.InputContainer == nil {
		return nil, fmt.Errorf("invalid info handle - input container not set")
	}

	numberOfVolumes, err := ih.InputContainer.NumberOfVolumes()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve number of volumes: %w", err)
	}

	if volumeIndex < 0 || volumeIndex >= numberOfVolumes {
		return nil, fmt.Errorf("invalid volume index: %d (available: 0-%d)", volumeIndex, numberOfVolumes-1)
	}

	volume, err := ih.InputContainer.Volume(volumeIndex)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve volume: %w", err)
	}

	return volume, nil
}

// SignalAbort sets the abort flag
func (ih *InfoHandle) SignalAbort() error {
	if ih == nil {
		return fmt.Errorf("invalid info handle")
	}

	ih.Abort = true
	return nil
}

// PrintContainerInfo prints information about the APFS container
func (ih *InfoHandle) PrintContainerInfo() error {
	if ih.InputContainer == nil {
		return fmt.Errorf("invalid info handle - input container not set")
	}

	fmt.Fprintf(ih.NotifyStream, "Apple File System (APFS) information:\n\n")

	// Print container identifier
	identifier, err := ih.InputContainer.Identifier()
	if err == nil {
		fmt.Fprintf(ih.NotifyStream, "Container identifier:\t\t%s\n", formatUUID(identifier))
	}

	// Print number of volumes
	numberOfVolumes, err := ih.InputContainer.NumberOfVolumes()
	if err != nil {
		return fmt.Errorf("unable to retrieve number of volumes: %w", err)
	}
	fmt.Fprintf(ih.NotifyStream, "Number of volumes:\t\t%d\n", numberOfVolumes)

	// Print container size
	size, err := ih.InputContainer.Size()
	if err == nil {
		fmt.Fprintf(ih.NotifyStream, "Container size:\t\t\t%d bytes\n", size)
	}

	fmt.Fprintf(ih.NotifyStream, "\n")

	// Print volume information based on VolumeIndex
	if ih.VolumeIndex == -1 {
		// Print all volumes
		for i := 0; i < numberOfVolumes; i++ {
			volume, err := ih.VolumeByIndex(i)
			if err != nil {
				return fmt.Errorf("unable to retrieve volume %d: %w", i, err)
			}

			if err := ih.PrintVolumeInfo(i, volume); err != nil {
				return fmt.Errorf("unable to print volume %d info: %w", i, err)
			}

			if i < numberOfVolumes-1 {
				fmt.Fprintf(ih.NotifyStream, "\n")
			}
		}
	} else {
		// Print specific volume
		if ih.VolumeIndex >= numberOfVolumes {
			return fmt.Errorf("volume index %d out of range (0-%d)", ih.VolumeIndex, numberOfVolumes-1)
		}

		volume, err := ih.VolumeByIndex(ih.VolumeIndex)
		if err != nil {
			return fmt.Errorf("unable to retrieve volume %d: %w", ih.VolumeIndex, err)
		}

		if err := ih.PrintVolumeInfo(ih.VolumeIndex, volume); err != nil {
			return fmt.Errorf("unable to print volume info: %w", err)
		}
	}

	return nil
}

// PrintVolumeInfo prints information about a specific volume
func (ih *InfoHandle) PrintVolumeInfo(volumeIndex int, volume *apfs.Volume) error {
	if volume == nil {
		return fmt.Errorf("invalid volume")
	}

	// Get volume name and identifier
	name, _ := volume.UTF8Name()
	identifier, _ := volume.Identifier()

	// Print boxed header
	headerText := fmt.Sprintf("Volume %d", volumeIndex+1)
	if name != "" {
		headerText += fmt.Sprintf(": %s", name)
	}

	boxWidth := max(len(headerText), len(formatUUIDArray(identifier))) + 10
	fmt.Fprintf(ih.NotifyStream, "╭─%s─╮\n", repeatChar('─', boxWidth))
	fmt.Fprintf(ih.NotifyStream, "│ %-*s │\n", boxWidth, headerText)
	fmt.Fprintf(ih.NotifyStream, "│ %-*s │\n", boxWidth, "UUID: "+formatUUIDArray(identifier))
	fmt.Fprintf(ih.NotifyStream, "╰─%s─╯\n\n", repeatChar('─', boxWidth))

	// Identity section: what the volume is for, and which group it belongs to.
	// Both are omitted when unset, which is the common case for a plain image.
	if roleName, err := volume.RoleName(); err == nil && roleName != "" {
		fmt.Fprintf(ih.NotifyStream, "  Identity\n")
		fmt.Fprintf(ih.NotifyStream, "    %-20s  %s\n", "Role", roleName)
		if groupID, err := volume.VolumeGroupIdentifier(); err == nil && groupID != ([16]byte{}) {
			fmt.Fprintf(ih.NotifyStream, "    %-20s  %s\n", "Volume group", formatUUIDArray(groupID))
		}
		fmt.Fprintf(ih.NotifyStream, "\n")
	}

	// Storage section
	fmt.Fprintf(ih.NotifyStream, "  Storage\n")
	if size, err := volume.Size(); err == nil {
		fmt.Fprintf(ih.NotifyStream, "    %-20s  %s (%s bytes)\n", "Size", formatBytes(size), formatNumber(size))
	}
	if isLocked, err := volume.IsLocked(); err == nil {
		lockedStr := "No"
		if isLocked {
			lockedStr = "Yes"
		}
		fmt.Fprintf(ih.NotifyStream, "    %-20s  %s\n", "Locked", lockedStr)
	}
	if volume.Superblock != nil {
		if unmountTime := volume.Superblock.UnmountTime; unmountTime != 0 {
			t := time.Unix(0, int64(unmountTime))
			fmt.Fprintf(ih.NotifyStream, "    %-20s  %s\n", "Unmount time", t.Format("2006-01-02 15:04:05"))
		}
	}
	fmt.Fprintf(ih.NotifyStream, "\n")

	// Contents section
	fmt.Fprintf(ih.NotifyStream, "  Contents\n")
	if volume.Superblock != nil {
		fmt.Fprintf(ih.NotifyStream, "    %-20s  %s\n", "Files", formatNumber(volume.Superblock.NumberOfFiles))
		fmt.Fprintf(ih.NotifyStream, "    %-20s  %s\n", "Directories", formatNumber(volume.Superblock.NumberOfDirectories))
		fmt.Fprintf(ih.NotifyStream, "    %-20s  %s\n", "Symlinks", formatNumber(volume.Superblock.NumberOfSymlinks))
		if numOther := volume.Superblock.NumberOfOtherFileSystemObjects; numOther > 0 {
			fmt.Fprintf(ih.NotifyStream, "    %-20s  %s\n", "Other objects", formatNumber(numOther))
		}
		if numSnapshots, err := volume.Superblock.NumberOfSnapshots(); err == nil && numSnapshots > 0 {
			fmt.Fprintf(ih.NotifyStream, "    %-20s  %s\n", "Snapshots", formatNumber(numSnapshots))
		}
	}
	fmt.Fprintf(ih.NotifyStream, "\n")

	// Features section
	fmt.Fprintf(ih.NotifyStream, "  Features\n")
	if compatibleNames, err := volume.CompatibleFeatureNames(); err == nil && len(compatibleNames) > 0 {
		for _, name := range compatibleNames {
			fmt.Fprintf(ih.NotifyStream, "    ✓ %s\n", name)
		}
	}
	if incompatibleNames, err := volume.IncompatibleFeatureNames(); err == nil && len(incompatibleNames) > 0 {
		for _, name := range incompatibleNames {
			fmt.Fprintf(ih.NotifyStream, "    ✓ %s\n", name)
		}
	}
	if readOnlyNames, err := volume.ReadOnlyCompatibleFeatureNames(); err == nil && len(readOnlyNames) > 0 {
		for _, name := range readOnlyNames {
			fmt.Fprintf(ih.NotifyStream, "    ✓ %s\n", name)
		}
	}

	return nil
}

// PrintFileSystemHierarchy prints the file system hierarchy
func (ih *InfoHandle) PrintFileSystemHierarchy() error {
	if ih.InputContainer == nil {
		return fmt.Errorf("invalid info handle - input container not set")
	}

	// Get the volume to display
	var volume *apfs.Volume
	var err error

	if ih.VolumeIndex == -1 {
		// Default to first volume if "all" was specified
		volume, err = ih.VolumeByIndex(0)
	} else {
		volume, err = ih.VolumeByIndex(ih.VolumeIndex)
	}

	if err != nil {
		return fmt.Errorf("unable to retrieve volume: %w", err)
	}

	// Get root file entry
	rootEntry, err := volume.RootDirectory()
	if err != nil {
		return fmt.Errorf("unable to get root directory: %w", err)
	}

	fmt.Fprintf(ih.NotifyStream, "File system hierarchy:\n")
	return ih.printFileEntryRecursive(rootEntry, "/", 0)
}

// printFileEntryRecursive recursively prints file entries with tree-style visualization
func (ih *InfoHandle) printFileEntryRecursive(entry *apfs.FileEntry, path string, depth int) error {
	return ih.printFileEntryRecursiveWithPrefix(entry, path, depth, "", true)
}

// printFileEntryRecursiveWithPrefix helper with tree prefix tracking
func (ih *InfoHandle) printFileEntryRecursiveWithPrefix(entry *apfs.FileEntry, path string, depth int, prefix string, isLast bool) error {
	if ih.Abort {
		return fmt.Errorf("aborted")
	}

	// ANSI color codes
	const (
		colorReset      = "\033[0m"
		colorBrightBlue = "\033[1;34m" // Directories
		colorCyan       = "\033[36m"   // Symlinks
		colorGreen      = "\033[32m"   // Executables
	)

	// Get file name and mode
	name, _ := entry.UTF8Name()
	fileMode, err := entry.FileMode()
	if err != nil {
		return err
	}

	// Determine file type and color
	fileType := fileMode & 0xf000
	permissions := fileMode & 0x01ff
	color := ""

	switch fileType {
	case 0x4000: // Directory
		color = colorBrightBlue
	case 0xa000: // Symlink
		color = colorCyan
	case 0x8000: // Regular file
		if permissions&0111 != 0 { // Executable
			color = colorGreen
		}
	}

	// Print current entry with tree characters
	if depth == 0 {
		// Root entry
		if color != "" {
			fmt.Fprintf(ih.NotifyStream, "%s%s%s\n", color, name, colorReset)
		} else {
			fmt.Fprintf(ih.NotifyStream, "%s\n", name)
		}
	} else {
		// Non-root: use tree characters
		connector := "├── "
		if isLast {
			connector = "└── "
		}

		if color != "" {
			fmt.Fprintf(ih.NotifyStream, "%s%s%s%s%s\n", prefix, connector, color, name, colorReset)
		} else {
			fmt.Fprintf(ih.NotifyStream, "%s%s%s\n", prefix, connector, name)
		}
	}

	// Process children if directory
	isDirectory := (fileMode & 0x4000) != 0
	if isDirectory {
		numberOfSubEntries, err := entry.NumberOfSubFileEntries()
		if err != nil {
			return err
		}

		for i := 0; i < numberOfSubEntries; i++ {
			subEntry, err := entry.SubFileEntryByIndex(i)
			if err != nil {
				continue
			}

			subName, _ := subEntry.UTF8Name()
			subPath := path
			if path != "/" {
				subPath += "/"
			}
			subPath += subName

			// Determine if this is the last child
			isLastChild := (i == numberOfSubEntries-1)

			// Build prefix for children
			var childPrefix string
			if depth == 0 {
				childPrefix = ""
			} else if isLast {
				childPrefix = prefix + "    " // 4 spaces for finished branches
			} else {
				childPrefix = prefix + "│   " // vertical line + 3 spaces
			}

			if err := ih.printFileEntryRecursiveWithPrefix(subEntry, subPath, depth+1, childPrefix, isLastChild); err != nil {
				return err
			}
		}
	}

	return nil
}

// PrintFileEntryByIdentifier prints information about a file entry by its identifier
func (ih *InfoHandle) PrintFileEntryByIdentifier(identifier uint64) error {
	if ih.InputContainer == nil {
		return fmt.Errorf("invalid info handle - input container not set")
	}

	// Get the volume
	var volume *apfs.Volume
	var err error

	if ih.VolumeIndex == -1 {
		volume, err = ih.VolumeByIndex(0)
	} else {
		volume, err = ih.VolumeByIndex(ih.VolumeIndex)
	}

	if err != nil {
		return fmt.Errorf("unable to retrieve volume: %w", err)
	}

	// Get file entry by identifier
	fileEntry, err := volume.FileEntryByIdentifier(identifier)
	if err != nil {
		return fmt.Errorf("unable to get file entry by identifier %d: %w", identifier, err)
	}

	return ih.printFileEntryInfo(fileEntry, "")
}

// PrintFileEntryByPath prints information about a file entry by its path
func (ih *InfoHandle) PrintFileEntryByPath(path string) error {
	if ih.InputContainer == nil {
		return fmt.Errorf("invalid info handle - input container not set")
	}

	// Get the volume
	var volume *apfs.Volume
	var err error

	if ih.VolumeIndex == -1 {
		volume, err = ih.VolumeByIndex(0)
	} else {
		volume, err = ih.VolumeByIndex(ih.VolumeIndex)
	}

	if err != nil {
		return fmt.Errorf("unable to retrieve volume: %w", err)
	}

	// Get file entry by path
	fileEntry, err := volume.FileEntryByPath(path)
	if err != nil {
		return fmt.Errorf("unable to get file entry by path %s: %w", path, err)
	}

	return ih.printFileEntryInfo(fileEntry, path)
}

// printFileEntryInfo prints detailed information about a file entry
func (ih *InfoHandle) printFileEntryInfo(entry *apfs.FileEntry, path string) error {
	if entry == nil {
		return fmt.Errorf("invalid file entry")
	}

	// Get name if path not provided
	if path == "" {
		name, _ := entry.UTF8Name()
		path = name
	}

	fmt.Fprintf(ih.NotifyStream, "File entry: %s\n", path)

	// Print identifier
	if identifier, err := entry.Identifier(); err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tIdentifier:\t\t%d\n", identifier)
	}

	// Print parent identifier
	if parentID, err := entry.ParentIdentifier(); err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tParent identifier:\t%d\n", parentID)
	}

	// Print file mode
	if fileMode, err := entry.FileMode(); err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tFile mode:\t\t0%o\n", fileMode)
	}

	// Print owner/group
	if uid, err := entry.OwnerIdentifier(); err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tOwner UID:\t\t%d\n", uid)
	}
	if gid, err := entry.GroupIdentifier(); err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tGroup GID:\t\t%d\n", gid)
	}

	// Print size
	if size, err := entry.Size(); err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tSize:\t\t\t%d bytes\n", size)
	}

	// Print number of links
	if links, err := entry.NumberOfLinks(); err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tNumber of links:\t%d\n", links)
	}

	// Print timestamps
	if ctime, err := entry.CreationTime(); err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tCreation time:\t\t%s\n", FormatTimestamp(ctime))
	}
	if mtime, err := entry.ModificationTime(); err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tModification time:\t%s\n", FormatTimestamp(mtime))
	}
	if atime, err := entry.AccessTime(); err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tAccess time:\t\t%s\n", FormatTimestamp(atime))
	}
	if itime, err := entry.InodeChangeTime(); err == nil {
		fmt.Fprintf(ih.NotifyStream, "\tInode change time:\t%s\n", FormatTimestamp(itime))
	}

	// Calculate MD5 if requested
	if ih.CalculateMD5 {
		fileMode, _ := entry.FileMode()
		isRegularFile := (fileMode & 0x8000) != 0
		if isRegularFile {
			md5Hash, err := CalculateMD5Hash(entry)
			if err == nil {
				fmt.Fprintf(ih.NotifyStream, "\tMD5 hash:\t\t%s\n", md5Hash)
			}
		}
	}

	return nil
}

// PrintFileEntries prints all file entries in bodyfile format
func (ih *InfoHandle) PrintFileEntries() error {
	if ih.InputContainer == nil {
		return fmt.Errorf("invalid info handle - input container not set")
	}

	if ih.BodyfileStream == nil {
		return fmt.Errorf("bodyfile stream not set")
	}

	// Get the volume
	var volume *apfs.Volume
	var err error

	if ih.VolumeIndex == -1 {
		volume, err = ih.VolumeByIndex(0)
	} else {
		volume, err = ih.VolumeByIndex(ih.VolumeIndex)
	}

	if err != nil {
		return fmt.Errorf("unable to retrieve volume: %w", err)
	}

	// Get root directory
	rootEntry, err := volume.RootDirectory()
	if err != nil {
		return fmt.Errorf("unable to get root directory: %w", err)
	}

	// Process all entries recursively
	return ih.printFileEntriesRecursive(rootEntry, "/")
}

// printFileEntriesRecursive recursively prints file entries in bodyfile format
func (ih *InfoHandle) printFileEntriesRecursive(entry *apfs.FileEntry, path string) error {
	if ih.Abort {
		return fmt.Errorf("aborted")
	}

	// Create bodyfile entry
	bodyfileEntry, err := FileEntryToBodyfileEntry(entry, path, ih.CalculateMD5)
	if err != nil {
		return fmt.Errorf("unable to create bodyfile entry: %w", err)
	}

	// Write to bodyfile stream
	if err := WriteBodyfileEntry(ih.BodyfileStream, bodyfileEntry); err != nil {
		return fmt.Errorf("unable to write bodyfile entry: %w", err)
	}

	// Process subdirectories
	fileMode, err := entry.FileMode()
	if err != nil {
		return err
	}

	isDirectory := (fileMode & 0x4000) != 0
	if isDirectory {
		numberOfSubEntries, err := entry.NumberOfSubFileEntries()
		if err != nil {
			return err
		}

		for i := 0; i < numberOfSubEntries; i++ {
			subEntry, err := entry.SubFileEntryByIndex(i)
			if err != nil {
				continue
			}

			subName, _ := subEntry.UTF8Name()
			subPath := path
			if path != "/" {
				subPath += "/"
			}
			subPath += subName

			if err := ih.printFileEntriesRecursive(subEntry, subPath); err != nil {
				return err
			}
		}
	}

	return nil
}
