//go:build !darwin && !linux

package hostwalk

import "testing"

func makeFIFO(t *testing.T, path string) bool {
	t.Helper()
	return false
}

func setXattr(t *testing.T, path, name string, value []byte) bool {
	t.Helper()
	return false
}
