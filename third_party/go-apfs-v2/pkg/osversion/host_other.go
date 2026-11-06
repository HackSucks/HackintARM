//go:build !darwin

package osversion

import (
	"context"
	"errors"
)

// Detect has no native macOS version to read on a non-Darwin host. Explicit
// compatibility profiles and version parsing remain available on every host.
func Detect(ctx context.Context) (Version, error) {
	if err := ctx.Err(); err != nil {
		return Version{}, err
	}
	return Version{}, errors.ErrUnsupported
}
