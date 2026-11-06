//go:build windows

package diskspace

import "golang.org/x/sys/windows"

// AvailableSpace returns the bytes still writable by this user in the volume
// holding dir. ok is false when the platform cannot report it, which a caller
// should treat as "do not know" rather than "none".
//
// GetDiskFreeSpaceEx's first output is the space available to the calling
// user, which is what matters here: a per-user quota can make a volume with
// free space still unable to take the write.
func AvailableSpace(dir string) (bytes uint64, ok bool, err error) {
	path, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, false, err
	}
	var availableToCaller, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(path, &availableToCaller, &total, &free); err != nil {
		return 0, false, err
	}
	return availableToCaller, true, nil
}
