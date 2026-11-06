//go:build !darwin

package hostdata

import "errors"

func nativeCompressionPathXattr(string, string, []byte) (int, error) { return 0, errors.ErrUnsupported }
