//go:build !darwin

package hostdata

import "os"

func filesystemXattrStorage(file *os.File) (bool, error) {
	return filesystemUsesAppleDouble(file)
}
