//go:build darwin || linux

package diskspace

import "golang.org/x/sys/unix"

// AvailableSpace returns the bytes still writable by this user in the file
// system holding dir. ok is false when the platform cannot report it, which a
// caller should treat as "do not know" rather than "none".
//
// It reports the space available to an unprivileged process, not the total
// free space: file systems reserve a slice for root, and a build that fits only
// into the reserve does not in fact fit.
func AvailableSpace(dir string) (bytes uint64, ok bool, err error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(dir, &stat); err != nil {
		return 0, false, err
	}
	return stat.Bavail * uint64(stat.Bsize), true, nil
}
