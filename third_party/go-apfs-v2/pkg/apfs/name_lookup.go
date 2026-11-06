package apfs

import (
	"strings"
	"syscall"
	"unicode/utf8"
)

// ValidateLookupName checks one existing-object pathname component. Malformed
// UTF-8 produces ENOENT before component length is considered. Well-formed but
// unassigned scalars remain lookup candidates; creation admission is separate.
// The limit counts the original UTF-16 units, before canonical decomposition.
func ValidateLookupName(name string) error {
	if strings.ContainsAny(name, "/\x00") {
		return syscall.EINVAL
	}
	if name == "" || !utf8.ValidString(name) {
		return syscall.ENOENT
	}
	units := 0
	for _, r := range name {
		units++
		if r > 0xffff {
			units++
		}
	}
	if units > 255 {
		return syscall.ENAMETOOLONG
	}
	return nil
}
