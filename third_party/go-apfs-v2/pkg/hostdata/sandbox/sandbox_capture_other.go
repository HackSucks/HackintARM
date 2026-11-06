//go:build !darwin

package sandbox

import "errors"

func captureAppSandbox() (bool, error) { return false, errors.ErrUnsupported }
