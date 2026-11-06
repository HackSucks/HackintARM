package captureprovenance

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/nativeevidence"
)

const retainedCatalog = "testdata/native-evidence/catalog.json"

// Reference selects original archived inputs for registered historical source
// sets. Unregistered inputs must pass the strict current-harness check. This
// selects provenance bytes only; it never substitutes retained native results
// for missing fresh CI observations.
func Reference(source fs.FS, recorded map[string]string) (fs.FS, error) {
	catalog, err := nativeevidence.ReadCatalog(source, retainedCatalog)
	if err != nil {
		return nil, fmt.Errorf("native reference catalog: %w", err)
	}
	if _, ok := catalog.Archives[nativeevidence.SourceSetDigest(recorded)]; ok {
		return nativeevidence.OriginalFS(context.Background(), source, catalog, recorded)
	}
	if err := Verify(source, recorded); err != nil {
		return nil, err
	}
	return source, nil
}

// VerifyReference checks the original capture harness rather than requiring a
// historical observation to have been collected by today's runner source.
func VerifyReference(source fs.FS, recorded map[string]string, required ...string) error {
	original, err := Reference(source, recorded)
	if err != nil {
		return err
	}
	if err = Verify(original, recorded); err != nil {
		return err
	}
	for _, name := range required {
		if _, err = ReadSource(original, recorded, name); err != nil {
			return err
		}
	}
	return nil
}

// ReadSource requires a caller-selected original/current reference and checks
// the recorded source hash. Missing original bytes always remain an error.
func ReadSource(reference fs.FS, recorded map[string]string, name string) ([]byte, error) {
	b, err := fs.ReadFile(reference, name)
	if err != nil {
		return nil, err
	}
	if nativeevidence.Digest(b) != recorded[name] {
		return nil, fmt.Errorf("native source digest mismatch %s", name)
	}
	return b, nil
}
