//go:build !darwin

package accesstime

import "os"

func recordReadAccess(_ *os.File) error {
	return ErrReadAccessUnsupported
}
