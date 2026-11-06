//go:build windows

package tools

// sanitizePathForHost applies the Windows filename rules.
func sanitizePathForHost(rel string) (string, bool) {
	return sanitizePathWindows(rel)
}
