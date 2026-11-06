package tools

import (
	"context"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// Capture through the contained parent for Linux O_PATH symlinks as well as
// ordinary objects. The projected descriptor and the selected entry must remain
// the same inode before and after capture. Concurrent namespace/metadata edits
// remain excluded; these observations cannot detect substitution-and-reversion.
func captureProjectionValues(ctx context.Context, root *os.Root, name string, projected *os.File, limits hostdata.XattrCaptureLimits) (map[string]appledouble.Value, error) {
	return captureProjectionValuesUsing(ctx, root, name, projected, limits, hostdata.CaptureXattrValuesAt)
}

func captureProjectionValuesUsing(ctx context.Context, root *os.Root, name string, projected *os.File, limits hostdata.XattrCaptureLimits, capture func(context.Context, *os.Root, string, hostdata.XattrCaptureLimits) (map[string]appledouble.Value, error)) (map[string]appledouble.Value, error) {
	held, err := projected.Stat()
	if err != nil {
		return nil, err
	}
	check := func() error {
		entry, err := root.Lstat(name)
		if err != nil {
			return err
		}
		if !os.SameFile(held, entry) || held.Mode().Type() != entry.Mode().Type() {
			return hostdata.ErrMetadataIdentity
		}
		return nil
	}
	if err = check(); err != nil {
		return nil, err
	}
	values, err := capture(ctx, root, name, limits)
	if err != nil {
		return nil, err
	}
	if err = check(); err != nil {
		return nil, err
	}
	return values, nil
}
