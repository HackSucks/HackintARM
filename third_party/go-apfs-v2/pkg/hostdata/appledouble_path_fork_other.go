//go:build !darwin

package hostdata

import (
	"errors"
	"io"
	"os"
)

func openPathResourceForkNative(*os.File, bool, uint32) (io.Closer, error) {
	return nil, errors.ErrUnsupported
}
