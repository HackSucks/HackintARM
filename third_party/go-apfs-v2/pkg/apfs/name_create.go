package apfs

import (
	"fmt"
	"github.com/deploymenttheory/go-apfs-v2/internal/nameunicode"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
	"strings"
	"syscall"
	"unicode/utf8"
)

// ValidateCreateName validates a new component against the explicit macOS target.
// Every scalar's admission is derived from actual native creation on that profile.
// This must not be applied to existing-object lookup or on-disk key decoding.
func ValidateCreateName(name string, target osversion.Version) error {
	if _, err := osversion.ProfileForMacOS(target); err != nil {
		return err
	}
	if name == "" || strings.ContainsAny(name, "/\x00") {
		return syscall.EINVAL
	}
	if !utf8.ValidString(name) {
		return syscall.EILSEQ
	}
	if name == "." || name == ".." {
		return syscall.EEXIST
	}
	if err := ValidateLookupName(name); err != nil {
		return err
	}
	for _, r := range name {
		if !nameunicode.APFSCreateAllowed(r, int(target.Major)) {
			return fmt.Errorf("U+%04X is not admitted by macOS%d: %w", r, target.Major, syscall.EILSEQ)
		}
	}
	return nil
}
