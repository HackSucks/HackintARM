package hostdata

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/deploymenttheory/go-apfs-v2/internal/darwinabi"
	"golang.org/x/sys/unix"
)

// Volume attributes describe the filesystem of this held object, including
// objects below its root. Query both the value and its validity: an unknown
// capability is not evidence that security metadata can be discarded.
type volumeCapabilities struct {
	Length       uint32
	Capabilities [4]uint32
	Valid        [4]uint32
}

func heldVolumeCapabilities(file *os.File) (volumeCapabilities, error) {
	var result volumeCapabilities
	m := nativeHeldMetadata{file: file}
	err := m.control(func(fd int32) error {
		list := unix.Attrlist{Bitmapcount: 5, Volattr: unix.ATTR_VOL_INFO | unix.ATTR_VOL_CAPABILITIES}
		_, err := darwinabi.Fgetattrlist(fd, &list, unsafe.Pointer(&result), unsafe.Sizeof(result), 0)
		return err
	})
	return result, err
}

func replacementVolumeACL(file *os.File) (bool, error) {
	result, err := heldVolumeCapabilities(file)
	if err != nil {
		return false, err
	}
	return replacementVolumeACLResult(result.Length, result.Capabilities[1], result.Valid[1])
}

func replacementVolumeACLResult(length, capabilities, valid uint32) (bool, error) {
	const extendedSecurity = 0x400 // VOL_CAP_INT_EXTENDED_SECURITY, sys/attr.h
	if length != 36 || valid&extendedSecurity == 0 {
		return false, fmt.Errorf("%w: volume ACL capability unavailable", ErrUnsupportedReplacement)
	}
	return capabilities&extendedSecurity != 0, nil
}
