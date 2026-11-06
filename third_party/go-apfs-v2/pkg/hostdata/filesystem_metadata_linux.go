package hostdata

import (
	"os"

	"golang.org/x/sys/unix"
)

func filesystemUsesAppleDouble(file *os.File) (selected bool, err error) {
	err = withXattrDescriptor(file, func(fd int) error { var e error; selected, e = filesystemUsesAppleDoubleFD(fd); return e })
	return
}
func filesystemUsesAppleDoubleFD(fd int) (bool, error) {
	var stat unix.Statfs_t
	err := unix.Fstatfs(fd, &stat)
	return stat.Type == unix.MSDOS_SUPER_MAGIC || stat.Type == unix.EXFAT_SUPER_MAGIC, err
}
func openFilesystemSidecar(root *os.Root, name string) (*os.File, error) {
	return OpenMetadataFileRead(root, name)
}
