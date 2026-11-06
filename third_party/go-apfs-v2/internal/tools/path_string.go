// Path string manipulation utilities for APFS tools
package tools

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// ParseHexadecimalToUint32 converts a hexadecimal string to a uint32
// Corresponds to path_string_copy_hexadecimal_to_integer_32_bit
func ParseHexadecimalToUint32(hexString string) (uint32, error) {
	if hexString == "" {
		return 0, fmt.Errorf("empty hexadecimal string")
	}

	value, err := strconv.ParseUint(hexString, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid hexadecimal string: %w", err)
	}

	return uint32(value), nil
}

// UnescapePath converts an escaped path back to its original form
// This is the inverse of escapePath and handles:
// - \\ -> \
// - \x## -> control character
// - \U######## -> Unicode character
// - \| -> |
// Corresponds to path_string_copy_to_file_entry_path
func UnescapePath(escapedPath string) (string, error) {
	if escapedPath == "" {
		return "", nil
	}

	var result strings.Builder
	result.Grow(len(escapedPath))

	i := 0
	for i < len(escapedPath) {
		if escapedPath[i] == '\\' {
			if i+1 >= len(escapedPath) {
				return "", fmt.Errorf("incomplete escape sequence at end of path")
			}

			nextChar := escapedPath[i+1]
			switch nextChar {
			case '\\':
				// \\ -> \
				result.WriteByte('\\')
				i += 2
			case '|':
				// \| -> |
				result.WriteByte('|')
				i += 2
			case 'x':
				// \x## -> control character (2 hex digits)
				if i+3 >= len(escapedPath) {
					return "", fmt.Errorf("incomplete \\x escape sequence at position %d", i)
				}
				hexValue, err := ParseHexadecimalToUint32(escapedPath[i+2 : i+4])
				if err != nil {
					return "", fmt.Errorf("invalid \\x escape sequence at position %d: %w", i, err)
				}
				// Validate it's a control character
				if !((hexValue <= 0x1f) || (hexValue >= 0x7f && hexValue <= 0x9f)) {
					return "", fmt.Errorf("invalid \\x escape value 0x%02x at position %d (not a control character)", hexValue, i)
				}
				result.WriteRune(rune(hexValue))
				i += 4
			case 'U':
				// \U######## -> Unicode character (8 hex digits)
				if i+9 >= len(escapedPath) {
					return "", fmt.Errorf("incomplete \\U escape sequence at position %d", i)
				}
				hexValue, err := strconv.ParseUint(escapedPath[i+2:i+10], 16, 32)
				if err != nil {
					return "", fmt.Errorf("invalid \\U escape sequence at position %d: %w", i, err)
				}
				result.WriteRune(rune(hexValue))
				i += 10
			default:
				return "", fmt.Errorf("invalid escape sequence \\%c at position %d", nextChar, i)
			}
		} else {
			result.WriteByte(escapedPath[i])
			i++
		}
	}

	return result.String(), nil
}

// NormalizePath normalizes a path by cleaning it and converting to forward slashes
func NormalizePath(path string) string {
	// Clean the path (remove .., ., etc.)
	cleaned := filepath.Clean(path)
	// Convert to forward slashes for consistency
	return filepath.ToSlash(cleaned)
}

// JoinPath joins path segments with forward slashes
func JoinPath(segments ...string) string {
	return filepath.ToSlash(filepath.Join(segments...))
}

// SplitPath splits a path into its components
func SplitPath(path string) []string {
	// Normalize the path first
	normalized := NormalizePath(path)

	// Remove leading slash if present
	normalized = strings.TrimPrefix(normalized, "/")

	// Split on forward slashes
	if normalized == "" {
		return []string{}
	}

	return strings.Split(normalized, "/")
}

// IsAbsolutePath checks if a path is absolute
func IsAbsolutePath(path string) bool {
	return filepath.IsAbs(path)
}

// Basename returns the last element of a path
func Basename(path string) string {
	return filepath.Base(path)
}

// Dirname returns the directory portion of a path
func Dirname(path string) string {
	return filepath.Dir(path)
}

// PathContainsEscapes checks if a path contains escape sequences
func PathContainsEscapes(path string) bool {
	return strings.Contains(path, "\\")
}

// ValidatePath checks if a path is valid and doesn't contain null bytes
func ValidatePath(path string) error {
	if strings.Contains(path, "\x00") {
		return fmt.Errorf("path contains null byte")
	}
	return nil
}
