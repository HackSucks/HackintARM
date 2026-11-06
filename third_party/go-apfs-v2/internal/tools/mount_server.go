// Platform-independent mount server abstraction.
package tools

// MountServer is the platform-independent handle to a mounted file system.
// On FUSE platforms it is backed by *fuse.Server.
type MountServer interface {
	Unmount() error
}
