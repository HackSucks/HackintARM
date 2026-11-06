//go:build !darwin

package hostdata

import (
	"errors"
	"os"
)

func newHeldMetadata(*os.File) (heldMetadataOperations, error) { return nil, errors.ErrUnsupported }
