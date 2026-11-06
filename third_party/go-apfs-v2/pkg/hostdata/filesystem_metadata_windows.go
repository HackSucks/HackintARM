package hostdata

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func filesystemUsesAppleDouble(file *os.File) (selected bool, err error) {
	err = withXattrDescriptor(file, func(fd int) error { var e error; selected, e = filesystemUsesAppleDoubleFD(fd); return e })
	return
}
func filesystemUsesAppleDoubleFD(fd int) (bool, error) {
	var name [256]uint16
	err := windows.GetVolumeInformationByHandle(windows.Handle(fd), nil, 0, nil, nil, nil, &name[0], uint32(len(name)))
	return filesystemFATName(windows.UTF16ToString(name[:])), err
}
func filesystemFATName(name string) bool {
	return strings.EqualFold(name, "FAT") || strings.EqualFold(name, "FAT32") || strings.EqualFold(name, "exFAT")
}

func openFilesystemSidecar(root *os.Root, name string) (*os.File, error) {
	return openMetadataChecked(root, name, func(root *os.Root, name string, _ os.FileInfo) (*os.File, error) {
		return metadataParent(root, name, func(parent *os.File, base string) (*os.File, error) {
			return openWindowsMetadataRights(parent, base, windows.SYNCHRONIZE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES|windows.FILE_READ_DATA)
		})
	})
}

// FAT does not store per-entry Windows security descriptors or Unix owners.
func filesystemMetadataSameOwner(os.FileInfo, os.FileInfo) bool { return true }
