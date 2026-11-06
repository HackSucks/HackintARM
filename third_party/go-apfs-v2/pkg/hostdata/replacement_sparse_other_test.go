//go:build !windows

package hostdata

import "os"

// Unix regular files allocate holes on extension; NTFS requires an explicit flag.
func replacementSparse(_ *os.File) error { return nil }
