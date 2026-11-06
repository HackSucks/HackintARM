package hostdata

import "os"

// Darwin's VFS already performs filesystem-specific AppleDouble dispatch.
func filesystemUsesAppleDouble(*os.File) (bool, error) { return false, nil }

func openFilesystemSidecar(root *os.Root, name string) (*os.File, error) {
	return OpenMetadataFileRead(root, name)
}
