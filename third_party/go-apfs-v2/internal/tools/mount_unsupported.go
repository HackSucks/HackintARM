//go:build !linux && !darwin

// Stub for platforms without FUSE support (e.g. Windows).
package tools

import "fmt"

// MountVolumeFS is not supported on this platform.
func MountVolumeFS(volume VolumeFS, name, mountPoint string, debug bool) (MountServer, error) {
	return nil, fmt.Errorf("mount requires FUSE and is not supported on this platform; use 'apfs extract' to copy files instead")
}
