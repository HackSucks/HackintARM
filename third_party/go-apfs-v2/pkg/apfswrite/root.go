// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Deployment Theory.

package apfswrite

import (
	"fmt"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/internal/unixmode"
)

// setRoot retains caller-supplied metadata on the special root inode, without
// counting it as a user directory or allocating a new inode number. Stream IDs
// follow the user entries so metadata-free roots retain the existing layout.
func (b volCtx) setRoot(source *Entry, nextOID uint64) (uint64, error) {
	if source == nil {
		return nextOID, nil
	}
	root := *source
	if kind := root.Mode.Type(); kind != 0 && kind != os.ModeDir {
		return nextOID, fmt.Errorf("apfswrite: volume root must be a directory, got %s", kind)
	}
	// The root's name and payload have never represented a user file. Work on
	// a copy so neither normalization nor validation mutates the caller's tree.
	if root.DataValue != nil {
		return nextOID, fmt.Errorf("apfswrite: root cannot have DataValue")
	}
	root.Name, root.Data = "root", nil
	root.Mode |= os.ModeDir
	embedded, streamed, flags, bsdFlags, err := prepareXattrs(&root)
	if err != nil {
		return nextOID, err
	}
	mode := uint16(sIFDIR) | unixmode.Permissions(source.Mode, 0755, source.ModeExplicit || source.Mode != 0)
	times, err := b.inodeTimes(&root)
	if err != nil {
		return nextOID, fmt.Errorf("apfswrite: root timestamps: %w", err)
	}
	b.root = &builderEntry{name: "root", oid: rootDirInoNum, parent: rootDirParent, isDir: true, mode: mode, uid: root.UID, gid: root.GID, times: times, timeSet: true, xattrs: embedded, xattrFlags: flags, bsdFlags: bsdFlags}
	return b.addXattrStreams(b.root, streamed, nextOID), nil
}
