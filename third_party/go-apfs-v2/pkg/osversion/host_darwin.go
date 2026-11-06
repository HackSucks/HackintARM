package osversion

import (
	"context"
	"golang.org/x/sys/unix"
)

// Detect reads the current macOS product version through the typed libSystem
// sysctl wrapper. Foreign callers supply a target with Parse instead; Detect
// does not infer a macOS target from a Linux or Windows host.
func Detect(ctx context.Context) (Version, error) {
	return detect(ctx, func() (string, error) { return unix.Sysctl("kern.osproductversion") })
}
