//go:build !darwin

package hostdata

import (
	"context"
	"errors"
	"os"
)

func openNativeCompressionInput(context.Context, string) (CompressionInput, error) {
	return nil, errors.ErrUnsupported
}

func newNativeCompressionInput(context.Context, *os.File) (CompressionInput, error) {
	return nil, errors.ErrUnsupported
}
