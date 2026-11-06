//go:build !darwin

package hostdata

import "errors"

func nativeCompressionStat(int) (uint32, uint64, error) { return 0, 0, errors.ErrUnsupported }
func nativeCompressionVolumeFlags(int) (uint32, error)  { return 0, errors.ErrUnsupported }
func nativeCompressionVolume(int) (CompressionVolume, error) {
	return CompressionVolume{}, errors.ErrUnsupported
}
