package hostdata

import "golang.org/x/sys/unix"

// Linux has no transparent compression and no XATTR_SHOWCOMPRESSION, so there
// is nothing here that the ordinary wrappers cannot see; compare
// xattr_darwin.go, which needs option-aware libSystem calls to reach a compressed file's
// content.

func listXattrNames(path string) ([]string, error) {
	return readXattrNames(func(buf []byte) (int, error) { return unix.Llistxattr(path, buf) }, MaxXattrListSize)
}

func getXattr(path, name string) ([]byte, error) {
	size, err := unix.Lgetxattr(path, name, nil)
	if err != nil {
		return nil, err
	}
	if size == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, size)
	size, err = unix.Lgetxattr(path, name, buf)
	if err != nil {
		return nil, err
	}
	return buf[:size], nil
}
