//go:build !darwin

package hostdata

import (
	"errors"
	"os"
)

func newHostObjectAttributes(*os.File) (objectAttributes, error) { return nil, errors.ErrUnsupported }
