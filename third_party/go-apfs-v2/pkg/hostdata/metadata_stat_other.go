//go:build !windows

package hostdata

import "os"

func statMetadata(root *os.Root, name string) (os.FileInfo, error) {
	return root.Lstat(name)
}
