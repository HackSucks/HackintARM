package hostdata

import "os"

func filesystemXattrStorage(file *os.File) (bool, error) {
	result, err := heldVolumeCapabilities(file)
	if err != nil {
		return false, err
	}
	return filesystemXattrStorageResult(result.Length, result.Capabilities[1], result.Valid[1])
}

func filesystemXattrStorageResult(length, capabilities, valid uint32) (bool, error) {
	const extendedAttributes = 0x4000 // VOL_CAP_INT_EXTENDED_ATTR, sys/attr.h
	if length != 36 {
		return false, os.ErrInvalid
	}
	// Apple pathFileSystemUsesXattrFiles treats unknown native xattr support as
	// companion-file storage. ACL restoration has a different validity policy.
	return valid&extendedAttributes == 0 || capabilities&extendedAttributes == 0, nil
}
