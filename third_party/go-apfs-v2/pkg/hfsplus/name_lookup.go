package hfsplus

import (
	"strings"
	"syscall"
)

// ValidateLookupName checks one existing-object pathname component using HFS's
// catalog conversion. Illegal UTF-8 bytes are percent escaped, not replaced by
// U+FFFD or universally rejected. The 255-unit limit applies after that escaping
// and frozen HFS canonical decomposition. Directory search is authorized first.
func ValidateLookupName(name string) error {
	_, err := NormalizeLookupName(name)
	return err
}

// NormalizeLookupName returns the normalized POSIX spelling for one raw native
// component. Illegal bytes become percent escapes before length validation.
// The result can be supplied to the io/fs reader, whose raw input contract still
// requires valid UTF-8. This helper does not authorize directory search.
func NormalizeLookupName(name string) (string, error) {
	if strings.ContainsAny(name, "/\x00") {
		return "", syscall.EINVAL
	}
	if name == "" {
		return "", syscall.ENOENT
	}
	normalized := normalizeName(name)
	units := 0
	for _, r := range normalized {
		units++
		if r > 0xffff {
			units++
		}
	}
	if units > 255 {
		return "", syscall.ENAMETOOLONG
	}
	return normalized, nil
}
