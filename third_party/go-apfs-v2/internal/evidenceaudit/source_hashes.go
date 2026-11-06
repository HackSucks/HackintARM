package evidenceaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
)

// SourceHashes hashes the exact bytes selected by slash-separated repository
// patterns. Both patterns and report keys use io/fs names on every host, so a
// Windows capture can be independently verified on macOS without rewriting
// names or normalizing source contents. Unmatched patterns fail closed.
func SourceHashes(sources fs.FS, patterns []string) (map[string]string, error) {
	hashes := make(map[string]string)
	for _, pattern := range patterns {
		names, err := fs.Glob(sources, pattern)
		if err != nil {
			return nil, err
		}
		if len(names) == 0 {
			return nil, fmt.Errorf("source pattern %q: %w", pattern, fs.ErrNotExist)
		}
		for _, name := range names {
			data, err := fs.ReadFile(sources, name)
			if err != nil {
				return nil, err
			}
			sum := sha256.Sum256(data)
			hashes[name] = hex.EncodeToString(sum[:])
		}
	}
	return hashes, nil
}
