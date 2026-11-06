//go:build !windows

package hostdata

import "os"

func openPathOrdinary(name string, flags int, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(name, flags, mode)
}

func chmodPathBacking(file *os.File, mode os.FileMode) error { return file.Chmod(mode) }
