package hostdata

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// metadataParentPath resolves directory components before Windows can collapse
// link/.. lexically. Every observation and the eventual open remain rooted.
// It does not freeze the namespace between observations.
func metadataParentPath(root *os.Root, name string) (string, error) {
	split := func(s string) []string {
		return strings.FieldsFunc(s, func(r rune) bool { return r == '/' || (os.PathSeparator == '\\' && r == '\\') })
	}
	pending := split(name)
	var resolved []string
	links := 0
	for len(pending) > 0 {
		part := pending[0]
		pending = pending[1:]
		switch part {
		case ".":
			continue
		case "..":
			if len(resolved) == 0 {
				return "", os.ErrInvalid
			}
			resolved = resolved[:len(resolved)-1]
			continue
		}
		candidate := filepath.Join(append(append([]string{}, resolved...), part)...)
		info, err := root.Lstat(candidate)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			links++
			if links > 40 {
				return "", syscall.ELOOP
			}
			target, err := root.Readlink(candidate)
			if err != nil {
				return "", err
			}
			if target == "" || filepath.IsAbs(target) || filepath.VolumeName(target) != "" || os.IsPathSeparator(target[0]) {
				return "", os.ErrInvalid
			}
			pending = append(split(target), pending...)
			continue
		}
		if !info.IsDir() {
			return "", syscall.ENOTDIR
		}
		resolved = append(resolved, part)
	}
	if len(resolved) == 0 {
		return ".", nil
	}
	return filepath.Join(resolved...), nil
}
