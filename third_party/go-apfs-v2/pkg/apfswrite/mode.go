package apfswrite

import "github.com/deploymenttheory/go-apfs-v2/internal/unixmode"

// resolvedMode selects the type separately from the explicit/defaulted
// permission bits. Hard-link aliases share the first entry's resolved inode.
func (e *Entry) resolvedMode() uint16 {
	kind, fallback := uint16(sIFREG), uint16(0644)
	switch {
	case e.isSymlinkEntry():
		kind, fallback = sIFLNK, 0755
	case e.isDirEntry():
		kind, fallback = sIFDIR, 0755
	}
	return kind | unixmode.Permissions(e.Mode, fallback, e.ModeExplicit)
}
