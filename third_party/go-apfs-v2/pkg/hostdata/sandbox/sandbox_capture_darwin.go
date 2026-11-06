package sandbox

import "github.com/deploymenttheory/go-apfs-v2/internal/darwinabi"

// The required symbol is linked by the typed wrapper, rather than discovered
// at runtime. Keep the provider seam for deterministic capture failure tests.
var loadAppSandbox = func() (func() bool, error) { return darwinabi.AppSandboxed, nil }

func captureAppSandbox() (bool, error) {
	query, err := loadAppSandbox()
	if err != nil {
		return false, err
	}
	return query(), nil
}
