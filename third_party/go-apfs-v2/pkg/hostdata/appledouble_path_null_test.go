package hostdata

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestAppleDoublePathCapturedNullDevice(t *testing.T) {
	for _, operation := range []PathAppleDoubleOperation{PathPackAppleDouble, PathUnpackAppleDouble} {
		t.Run(map[PathAppleDoubleOperation]string{PathPackAppleDouble: "pack", PathUnpackAppleDouble: "unpack"}[operation], func(t *testing.T) {
			source := objectFixture(t)
			metadata := source.meta.(*LogicalMetadata)
			metadata.state.Stat.Mode = 0020666
			metadata.state.Security.Mode = 0020666
			mode := uint32(0020666)
			metadata.state.Security.Properties.Mode = &mode
			contextState := pathCapturedFixture(t, source, nil)
			target := filepath.Join(t.TempDir(), "destination")
			options := AppleDoublePathOptions{Operation: operation, Pack: DefaultObjectPackOptions(), Unpack: DefaultObjectUnpackOptions(), MaxOpenAttempts: 4, Captured: contextState}
			result, err := CopyAppleDoublePath(context.Background(), os.DevNull, target, options)
			if operation == PathPackAppleDouble {
				if err != nil || result.Lifecycle.Code != 0 {
					t.Fatalf("%+v %v", result, err)
				}
				data, e := os.ReadFile(target)
				if e != nil {
					t.Fatal(e)
				}
				decoded, e := appledouble.DecodeStream(context.Background(), bytes.NewReader(data), appledouble.DefaultStreamLimits())
				if e != nil || len(decoded.Attrs) != 0 {
					t.Fatal(decoded, e)
				}
			} else if err == nil || result.Lifecycle.Code != -1 {
				t.Fatalf("%+v %v", result, err)
			}
			info, e := os.Stat(target)
			if e != nil || !info.Mode().IsRegular() {
				t.Fatal(info, e)
			}
			logical, _, e := contextState.Destination.LogicalSnapshot()
			if e != nil || logical.Stat.Mode&0170000 != 0100000 {
				t.Fatal(logical, e)
			}
			file, e := os.Open(os.DevNull)
			if e != nil {
				t.Fatal(e)
			}
			if e = file.Close(); e != nil {
				t.Fatal(e)
			}
		})
	}
	// The exception is tied to both the canonical name and explicit source kind.
	// A caller cannot label an ordinary path as a character device to bypass type
	// checks, nor label a null device as an ordinary file to invent its metadata.
	for _, canonical := range []bool{false, true} {
		source := objectFixture(t)
		path := filepath.Join(t.TempDir(), "ordinary")
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
		if canonical {
			path = os.DevNull
		} else {
			metadata := source.meta.(*LogicalMetadata)
			metadata.state.Stat.Mode = 0020666
			metadata.state.Security.Mode = 0020666
			mode := uint32(0020666)
			metadata.state.Security.Properties.Mode = &mode
		}
		opts := AppleDoublePathOptions{Operation: PathPackAppleDouble, Pack: DefaultObjectPackOptions(), MaxOpenAttempts: 4, Captured: pathCapturedFixture(t, source, nil)}
		_, err := CopyAppleDoublePath(context.Background(), path, filepath.Join(t.TempDir(), "destination"), opts)
		if !errors.Is(err, errors.ErrUnsupported) && !errors.Is(err, ErrMetadataIdentity) {
			t.Fatal(err)
		}
	}
}
