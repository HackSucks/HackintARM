//go:build !windows

package tools

// sanitizePathForHost is a no-op on Unix-like systems, where any byte except
// '/' and NUL is valid in a filename and the io/fs layer already excludes
// both. Names are preserved verbatim.
func sanitizePathForHost(rel string) (string, bool) {
	return rel, false
}
