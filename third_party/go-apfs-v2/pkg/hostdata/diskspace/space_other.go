//go:build !darwin && !linux && !windows

package diskspace

// AvailableSpace cannot report free space on this platform. It reports ok
// false rather than an error, so a caller checking whether a build will fit
// simply proceeds instead of refusing on a platform that cannot tell it.
func AvailableSpace(dir string) (bytes uint64, ok bool, err error) {
	return 0, false, nil
}
