//go:build !darwin

package hostdata

import (
	"context"
	"errors"
	"os"
)

func openNativeResourceForkContext(context.Context, int, bool) (*os.File, error) {
	return nil, errors.ErrUnsupported
}
