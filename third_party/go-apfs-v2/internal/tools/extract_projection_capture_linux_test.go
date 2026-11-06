package tools

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

func TestProjectionLinuxSymlinkNativeBaseline(t *testing.T) {
	for _, dangling := range []bool{false, true} {
		p, _, store := projectionFixture(t)
		target := filepath.Join(t.TempDir(), "outside")
		if !dangling {
			if err := os.WriteFile(target, []byte("unchanged target"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(target, filepath.Join(p, "link")); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(p)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		e := &Extractor{}
		records := []metatransport.Record{{Original: "link", Materialized: "link", Kind: "symlink", MaterializedKind: "symlink"}}
		limits := hostdata.XattrCaptureLimits{NameBytes: hostdata.MaxXattrListSize, ValueBytes: 65536, TotalBytes: 1 << 20}
		err = e.projectCarrier(context.Background(), root, store, records, limits, newNativeProjection, hostdata.CaptureXattrs, captureProjectionValues)
		if err != nil || e.projectionError() != nil || !records[0].NativeCaptured || records[0].NativeUnsupported {
			t.Fatal(records, err, e.projectionError())
		}
		if !dangling {
			if data, err := os.ReadFile(target); err != nil || string(data) != "unchanged target" {
				t.Fatal(string(data), err)
			}
		}
	}
}
