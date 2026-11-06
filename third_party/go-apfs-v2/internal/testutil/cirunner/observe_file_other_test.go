//go:build !windows

package cirunner

import (
	"os"
	"testing"
)

func createMovableFile(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}
