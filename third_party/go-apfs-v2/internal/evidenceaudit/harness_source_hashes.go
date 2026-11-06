package evidenceaudit

import (
	"fmt"
	"io/fs"
)

// HarnessSourceHashes binds a qualification's explicit inputs together with the
// shared command runner, its workflow entry point and its setup action. All
// platform variants and other files in the runner tree are retained, including
// headers, assembly and test fixtures; the receiving host's build tags do not
// narrow this inventory. At least one top-level Go runner source is required.
//
// Report keys and exact-byte hashing follow SourceHashes. Caller patterns are
// not modified, and an unreadable or incomplete inventory never returns partial
// provenance. This function describes current inputs, not historical captures.
func HarnessSourceHashes(sources fs.FS, patterns []string) (map[string]string, error) {
	bound := append([]string(nil), patterns...)
	bound = append(bound, "internal/testutil/cirunner/*.go", "scripts/ci-run.go", ".github/actions/setup-ci-runner/action.yml")
	if err := fs.WalkDir(sources, "internal/testutil/cirunner", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			bound = append(bound, name)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("CI runner source inventory: %w", err)
	}
	return SourceHashes(sources, bound)
}
