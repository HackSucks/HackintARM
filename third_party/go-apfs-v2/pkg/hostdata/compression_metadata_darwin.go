package hostdata

import (
	"golang.org/x/sys/unix"
	"io/fs"
)

func nativeCompressionStat(fd int) (uint32, uint64, error) {
	return compressionStatUsing(fd, unix.Fstat)
}

func compressionStatUsing(fd int, stat func(int, *unix.Stat_t) error) (uint32, uint64, error) {
	var state unix.Stat_t
	if err := stat(fd, &state); err != nil {
		return 0, 0, err
	}
	if state.Size < 0 {
		return 0, 0, fs.ErrInvalid
	}
	return state.Flags, uint64(state.Size), nil
}
func nativeCompressionVolumeFlags(fd int) (uint32, error) {
	v, err := nativeCompressionVolume(fd)
	return v.Flags, err
}
func nativeCompressionVolume(fd int) (CompressionVolume, error) {
	var state unix.Statfs_t
	if err := unix.Fstatfs(fd, &state); err != nil {
		return CompressionVolume{}, err
	}
	return CompressionVolume{Filesystem: unix.ByteSliceToString(state.Fstypename[:]), Flags: state.Flags}, nil
}
