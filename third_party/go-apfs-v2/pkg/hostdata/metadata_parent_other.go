//go:build !windows

package hostdata

import "os"

func openMetadataParent(root *os.Root, name string) (*os.File, error) { return root.Open(name) }
