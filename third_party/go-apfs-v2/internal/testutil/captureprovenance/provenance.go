// Package captureprovenance binds native observations to the exact CI harness.
package captureprovenance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/internal/evidenceaudit"
)

var implementation = []string{
	"internal/testutil/captureprovenance/provenance.go",
	"internal/evidenceaudit/harness_source_hashes.go",
	"internal/evidenceaudit/source_hashes.go",
}

// Inventory returns current exact-byte hashes for all runner platforms, its
// workflow entry points, and the implementations that collect these hashes.
// Historical observations must never be relabeled with this inventory.
func Inventory(source fs.FS) (map[string]string, error) {
	return evidenceaudit.HarnessSourceHashes(source, implementation)
}

// Verify requires every current harness input and rejects invented entries in
// its owned namespaces. Other native source-map entries are left intact for
// the caller's existing complete-inventory and source checks.
func Verify(source fs.FS, recorded map[string]string) error {
	expected, err := Inventory(source)
	if err != nil {
		return err
	}
	for name, want := range expected {
		if recorded[name] != want {
			return fmt.Errorf("stale or missing native harness source %s", name)
		}
	}
	for name := range recorded {
		if strings.HasPrefix(name, "internal/testutil/cirunner/") || strings.HasPrefix(name, "internal/testutil/captureprovenance/") {
			if _, ok := expected[name]; !ok {
				return fmt.Errorf("unexpected native harness source %s", name)
			}
		}
	}
	return nil
}

// Bind copies the complete harness into an owned artifact directory and adds
// its exact hashes to recorded only after all copies succeed. Relative keys are
// unchanged, so both aliased capture.go fixtures and repository-path fixtures
// can validate each archived source byte without consulting the checkout.
func Bind(source fs.FS, artifact string, recorded map[string]string) error {
	if artifact == "" || recorded == nil {
		return fmt.Errorf("native harness requires artifact directory and source map")
	}
	expected, err := Inventory(source)
	if err != nil {
		return err
	}
	for name, want := range expected {
		if prior, ok := recorded[name]; ok && prior != want {
			return fmt.Errorf("conflicting native harness source %s", name)
		}
		data, err := fs.ReadFile(source, name)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != want {
			return fmt.Errorf("native harness source changed during capture: %s", name)
		}
		target := filepath.Join(artifact, filepath.FromSlash(name))
		if err = os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		if err = os.WriteFile(target, data, 0644); err != nil {
			return err
		}
	}
	for name, want := range expected {
		recorded[name] = want
	}
	return nil
}
