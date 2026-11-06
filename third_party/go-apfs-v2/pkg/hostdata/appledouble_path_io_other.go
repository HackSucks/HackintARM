//go:build !darwin

package hostdata

import (
	"errors"
	"os"
	"path/filepath"
)

func openPathPayload(name string, flags int, mode uint32, nofollow, _ bool, _ int) (*os.File, error) {
	if nofollow {
		info, err := os.Lstat(name)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			// A foreign host has no writable link data stream. Acquire the link
			// itself anyway: a PACK write must fail at transfer, then perform the
			// native failed-PACK unlink lifecycle without touching its referent.
			return openPathLink(name, pathLinkAccess{os.OpenRoot, OpenMetadataFileRead, (*os.Root).Close})
		}
	}
	return openPathOrdinary(name, flags, pathFileMode(uint16(mode)))
}

// pathLinkAccess isolates acquisition and cleanup failures without replacing the
// contained no-follow provider used by production.
type pathLinkAccess struct {
	root  func(string) (*os.Root, error)
	file  func(*os.Root, string) (*os.File, error)
	close func(*os.Root) error
}

func openPathLink(name string, access pathLinkAccess) (*os.File, error) {
	root, err := access.root(filepath.Dir(name))
	if err != nil {
		return nil, err
	}
	file, err := access.file(root, filepath.Base(name))
	closeErr := access.close(root)
	if closeErr != nil && file != nil {
		err = errors.Join(err, file.Close())
		file = nil
	}
	return file, errors.Join(err, closeErr)
}
func pathUnlink(name string) error {
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return os.ErrPermission
	}
	return os.Remove(name)
}
func pathSingleWriter(*os.File) error { return errors.ErrUnsupported }
