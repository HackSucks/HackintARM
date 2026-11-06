package hostdata

import (
	"os"
	"path/filepath"
)

// ReadEntryType returns the entry's os.FileMode type bits (zero for a regular
// file), without reading data, ACLs or extended attributes. Intermediate links
// must stay within root; a final link is inspected, never followed. Basic
// attribute and parent-directory authorization remains effective. Windows may
// grant attribute visibility through directory-list permission on the parent.
//
// This is a point-in-time type observation, not a held identity, access guarantee
// or permission evaluator. Bind subsequent reads/writes to their own descriptors.
func ReadEntryType(root *os.Root, name string) (os.FileMode, error) {
	if root == nil || !filepath.IsLocal(name) {
		return 0, os.ErrInvalid
	}
	mode, err := readEntryType(root, name)
	if err != nil {
		return 0, &os.PathError{Op: "readentrytype", Path: name, Err: err}
	}
	return mode, nil
}
