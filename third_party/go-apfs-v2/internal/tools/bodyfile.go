// Bodyfile output functions for APFS
package tools

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

// BodyfileEntry represents a line in bodyfile format
// Format: MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
type BodyfileEntry struct {
	MD5Hash      string
	Name         string
	Inode        uint64
	Mode         string
	UID          uint32
	GID          uint32
	Size         uint64
	AccessTime   int64
	ModTime      int64
	ChangeTime   int64
	CreationTime int64
}

// FormatBodyfileLine formats a bodyfile entry as a line
func (be *BodyfileEntry) FormatBodyfileLine() string {
	return fmt.Sprintf("%s|%s|%d|%s|%d|%d|%d|%d|%d|%d|%d",
		be.MD5Hash,
		escapePath(be.Name),
		be.Inode,
		be.Mode,
		be.UID,
		be.GID,
		be.Size,
		be.AccessTime,
		be.ModTime,
		be.ChangeTime,
		be.CreationTime,
	)
}

// escapePath escapes special characters in a path for bodyfile format
// It handles:
// - Control characters (U+0-U+1f, U+7f-U+9f) -> \x##
// - Unicode surrogate characters and undefined Unicode -> \U########
// - Escape character (\) -> \\
// - Bodyfile separator (|) -> \|
func escapePath(path string) string {
	var result strings.Builder
	// Worst case: each character could expand to 10 characters
	result.Grow(len(path) * 10)

	for _, r := range path {
		// Replace control characters (U+0-U+1f, U+7f-U+9f) with \x##
		if (r <= 0x1f) || (r >= 0x7f && r <= 0x9f) {
			result.WriteString(fmt.Sprintf("\\x%02x", r))
		} else if shouldEscapeUnicode(r) {
			// Replace Unicode surrogate characters, undefined Unicode, and
			// observed unprintable characters with \U########
			result.WriteString(fmt.Sprintf("\\U%08x", r))
		} else if r == '\\' || r == '|' {
			// Escape backslash and pipe separator
			result.WriteRune('\\')
			result.WriteRune(r)
		} else {
			// Regular character
			result.WriteRune(r)
		}
	}

	return result.String()
}

// shouldEscapeUnicode determines if a Unicode character should be escaped as \U########
// This matches the C implementation logic for Unicode escaping
func shouldEscapeUnicode(r rune) bool {
	// Unicode surrogate characters (U+d800-U+dfff)
	if r >= 0xd800 && r <= 0xdfff {
		return true
	}

	// Undefined Unicode characters in range U+fdd0-U+fddf
	if r >= 0xfdd0 && r <= 0xfddf {
		return true
	}

	// Characters ending in FFFE or FFFF (undefined in each plane)
	if (r&0xffff) >= 0xfffe && (r&0xffff) <= 0xffff {
		return true
	}

	// Observed unprintable characters
	switch r {
	case 0x2028, 0x2029: // Line separator, paragraph separator
		return true
	case 0xe000: // Private use area start
		return true
	case 0xf8ff: // Private use area end
		return true
	case 0xf0000: // Supplementary private use area
		return true
	case 0xffffd: // Replacement character
		return true
	case 0x100000: // Private use plane 16
		return true
	}

	// Characters >= U+10fffd (beyond valid Unicode range)
	if r >= 0x10fffd {
		return true
	}

	return false
}

// FileEntryToBodyfileEntry converts a file entry to a bodyfile entry
func FileEntryToBodyfileEntry(entry *apfs.FileEntry, path string, calculateMD5 bool) (*BodyfileEntry, error) {
	if entry == nil {
		return nil, fmt.Errorf("invalid file entry")
	}

	be := &BodyfileEntry{
		Name: path,
	}

	// Get inode/identifier
	if identifier, err := entry.Identifier(); err == nil {
		be.Inode = identifier
	}

	// Get file mode
	if fileMode, err := entry.FileMode(); err == nil {
		be.Mode = formatFileMode(fileMode)
	}

	// Get owner/group
	if uid, err := entry.OwnerIdentifier(); err == nil {
		be.UID = uid
	}
	if gid, err := entry.GroupIdentifier(); err == nil {
		be.GID = gid
	}

	// Get size
	if size, err := entry.Size(); err == nil {
		be.Size = size
	}

	// Get timestamps (convert from nanoseconds to seconds)
	if atime, err := entry.AccessTime(); err == nil {
		be.AccessTime = atime / 1000000000 // Convert nanoseconds to seconds
	}
	if mtime, err := entry.ModificationTime(); err == nil {
		be.ModTime = mtime / 1000000000
	}
	if ctime, err := entry.InodeChangeTime(); err == nil {
		be.ChangeTime = ctime / 1000000000
	}
	if crtime, err := entry.CreationTime(); err == nil {
		be.CreationTime = crtime / 1000000000
	}

	// Calculate MD5 if requested
	if calculateMD5 {
		// Check if it's a regular file
		if fileMode, err := entry.FileMode(); err == nil {
			isRegularFile := (fileMode & 0x8000) != 0 // S_IFREG
			if isRegularFile {
				md5Hash, err := CalculateMD5Hash(entry)
				if err != nil {
					be.MD5Hash = "0" // Use "0" for errors
				} else {
					be.MD5Hash = md5Hash
				}
			} else {
				be.MD5Hash = "0"
			}
		} else {
			be.MD5Hash = "0"
		}
	} else {
		be.MD5Hash = "0"
	}

	return be, nil
}

// formatFileMode converts a file mode to ls-style string
func formatFileMode(mode uint16) string {
	// File type
	var fileType string
	switch mode & 0xF000 {
	case 0x1000: // FIFO
		fileType = "p"
	case 0x2000: // Character device
		fileType = "c"
	case 0x4000: // Directory
		fileType = "d"
	case 0x6000: // Block device
		fileType = "b"
	case 0x8000: // Regular file
		fileType = "-"
	case 0xA000: // Symbolic link
		fileType = "l"
	case 0xC000: // Socket
		fileType = "s"
	default:
		fileType = "?"
	}

	// Permissions
	perms := ""
	perms += formatPerm(mode, 0400, 0200, 0100, "r", "w", "x", mode&0x800 != 0, "s", "S") // User
	perms += formatPerm(mode, 0040, 0020, 0010, "r", "w", "x", mode&0x400 != 0, "s", "S") // Group
	perms += formatPerm(mode, 0004, 0002, 0001, "r", "w", "x", mode&0x200 != 0, "t", "T") // Other

	return fileType + perms
}

// formatPerm formats permission bits
func formatPerm(mode uint16, r, w, x uint16, rChar, wChar, xChar string, special bool, specialSet, specialUnset string) string {
	result := ""
	if mode&r != 0 {
		result += rChar
	} else {
		result += "-"
	}
	if mode&w != 0 {
		result += wChar
	} else {
		result += "-"
	}
	if special {
		result += specialSet
	} else if mode&x != 0 {
		result += xChar
	} else {
		if special {
			result += specialUnset
		} else {
			result += "-"
		}
	}
	return result
}

// WriteBodyfileEntry writes a bodyfile entry to a writer
func WriteBodyfileEntry(writer io.Writer, entry *BodyfileEntry) error {
	if writer == nil {
		return fmt.Errorf("invalid writer")
	}
	if entry == nil {
		return fmt.Errorf("invalid entry")
	}

	line := entry.FormatBodyfileLine()
	_, err := fmt.Fprintf(writer, "%s\n", line)
	return err
}

// UnixTimeToNanoseconds converts Unix timestamp to nanoseconds
func UnixTimeToNanoseconds(unixTime int64) int64 {
	return unixTime * 1000000000
}

// NanosecondsToUnixTime converts nanoseconds to Unix timestamp
func NanosecondsToUnixTime(nanos int64) int64 {
	return nanos / 1000000000
}

// FormatTimestamp formats a timestamp in nanoseconds to a readable string
func FormatTimestamp(nanos int64) string {
	seconds := nanos / 1000000000
	t := time.Unix(seconds, nanos%1000000000)
	return t.Format("2006-01-02 15:04:05.000000000 -0700")
}
