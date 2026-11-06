//go:build !darwin && !linux && !windows

package hostdata

import "os"

func filesystemUsesAppleDouble(*os.File) (bool, error) { return false, ErrXattrUnsupported }

func openFilesystemSidecar(*os.Root, string) (*os.File, error)  { return nil, ErrXattrUnsupported }
func filesystemMetadataSameOwner(os.FileInfo, os.FileInfo) bool { return false }
