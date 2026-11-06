// Package bsdflags selects image BSD flags without host-dependent constants.
package bsdflags

import (
	"fmt"
	"io/fs"
)

const Compressed uint32 = 0x20

// Select retains legacy compression inference for nil. Explicit values must
// have storage when UF_COMPRESSED is set. With the flag clear, any decmpfs
// attribute is inactive opaque metadata. HFS cannot encode bits outside its two flag
// bytes and Finder invisible bit. Refuse loss rather than silently masking.
func Select(selected *uint32, compressed, hfs bool) (uint32, error) {
	var flags uint32
	if compressed {
		flags = Compressed
	}
	if selected != nil {
		flags = *selected
		if flags&Compressed != 0 && !compressed {
			return 0, fmt.Errorf("BSD compression flag disagrees with decmpfs storage: %w", fs.ErrInvalid)
		}
	}
	if hfs && flags&^uint32(0x00ff80ff) != 0 {
		return 0, fmt.Errorf("BSD flags cannot be represented in HFS catalog: %w", fs.ErrInvalid)
	}
	return flags, nil
}

// HFS decodes the native catalog flag view, including legacy mode-less records,
// Finder invisible and file-lock normalization in HFS getbsdattr. It does not
// read compression payloads or apply mount ownership/authorization policy.
func HFS(owner, admin uint8, mode uint16, directory, locked bool, finder uint16) uint32 {
	var flags uint32
	if mode&0170000 != 0 {
		flags = uint32(owner) | uint32(admin)<<16
	}
	if !directory {
		if locked {
			if flags&(0x2|0x20000) == 0 {
				flags |= 0x2
			}
		} else {
			flags &^= 0x2 | 0x20000
		}
	}
	if finder&0x4000 != 0 {
		flags |= 0x8000
	}
	return flags
}
