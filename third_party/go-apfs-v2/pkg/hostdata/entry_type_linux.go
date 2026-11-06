package hostdata

import "os"

func readEntryType(root *os.Root, name string) (os.FileMode, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return 0, err
	}
	return info.Mode().Type(), nil
}
