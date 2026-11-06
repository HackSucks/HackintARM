package hfsplus

import "github.com/deploymenttheory/go-apfs-v2/internal/unixmode"

// hfsFileMode maps the resolved node type and Go permissions into BSD mode.
func hfsFileMode(n *fileNode) uint16 {
	kind, fallback := uint16(sIFREG), uint16(0644)
	switch {
	case n.isSymlink:
		kind, fallback = sIFLNK, 0755
	case n.isDir:
		kind, fallback = sIFDIR, 0755
	}
	return kind | unixmode.Permissions(n.entry.Mode, fallback, n.entry.ModeExplicit)
}
