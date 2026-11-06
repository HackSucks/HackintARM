// Device abstraction for disk images and partitions
package disk

import "io"

// Device is a random-access, sized, closable view of a disk image or a
// partition within one. Implementations must return partition-relative data
// from ReadAt when they represent a partition (as DMGReader does for the
// APFS partition inside a DMG).
type Device interface {
	io.ReaderAt
	Size() int64
	Close() error
}
