//go:build windows || plan9

package hostdata

import "os"

// Link reports that this platform does not expose inode identity through
// os.FileInfo, so hard links cannot be distinguished from separate files.
func Link(fi os.FileInfo) (LinkIdentity, bool) {
	return LinkIdentity{}, false
}
