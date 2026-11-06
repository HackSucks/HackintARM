//go:build !windows

package cirunner

import "os"

func openObservationFile(name string) (*os.File, error) { return os.Open(name) }
