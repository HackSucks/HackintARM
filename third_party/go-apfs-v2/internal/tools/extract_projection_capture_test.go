package tools

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

func TestProjectionBoundCaptureIdentity(t *testing.T) {
	for _, fault := range []string{"none", "closed-file", "closed-root", "missing", "replacement-before", "capture", "replacement-after", "removed-after"} {
		t.Run(fault, func(t *testing.T) {
			dir := t.TempDir()
			name := filepath.Join(dir, "file")
			if err := os.WriteFile(name, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			file, err := hostdata.OpenMetadataFile(root, "file")
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			replace := func() {
				t.Helper()
				if err := os.Rename(name, name+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, []byte("replacement"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			capture := func(context.Context, *os.Root, string, hostdata.XattrCaptureLimits) (map[string]appledouble.Value, error) {
				if fault == "capture" {
					return nil, io.ErrClosedPipe
				}
				if fault == "replacement-after" {
					replace()
				}
				if fault == "removed-after" {
					if err := os.Remove(name); err != nil {
						t.Fatal(err)
					}
				}
				return map[string]appledouble.Value{"user.value": bytes.NewReader([]byte("native"))}, nil
			}
			switch fault {
			case "closed-file":
				file.Close()
			case "closed-root":
				root.Close()
			case "missing":
				os.Remove(name)
			case "replacement-before":
				replace()
			}
			values, err := captureProjectionValuesUsing(context.Background(), root, "file", file, hostdata.XattrCaptureLimits{}, capture)
			if fault == "none" {
				if err != nil || values["user.value"].Size() != 6 {
					t.Fatal(values, err)
				}
				return
			}
			if err == nil || values != nil {
				t.Fatal("partial or substituted baseline", values, err)
			}
			if (fault == "replacement-before" || fault == "replacement-after") && !errors.Is(err, hostdata.ErrMetadataIdentity) {
				t.Fatal(err)
			}
			if fault == "capture" && !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal(err)
			}
		})
	}
}

func TestProjectionReadbackFailureKeepsPriorBaseline(t *testing.T) {
	for _, cause := range []error{io.ErrClosedPipe, hostdata.ErrXattrUnsupported} {
		p, _, store := projectionFixture(t)
		if err := os.WriteFile(filepath.Join(p, "file"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(p)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		prior, err := store.StoreAttributes(context.Background(), map[string][]byte{"host.generated": []byte("original")})
		if err != nil {
			t.Fatal(err)
		}
		records := []metatransport.Record{{Original: "file", Materialized: "file", Kind: "file", MaterializedKind: "file", NativeCaptured: true, NativeAttributes: prior}}
		e := &Extractor{}
		err = e.projectCarrier(context.Background(), root, store, records, hostdata.XattrCaptureLimits{}, func(*os.File) projectionBackend { return &projectionRecorder{} }, func(context.Context, *os.File, hostdata.XattrCaptureLimits) (map[string][]byte, error) {
			return nil, cause
		})
		if err != nil || !records[0].NativeCaptured || records[0].NativeUnsupported || !reflect.DeepEqual(prior, records[0].NativeAttributes) {
			t.Fatal(records, err)
		}
		results := e.NativeProjectionResults()
		if len(results) != 1 || !errors.Is(results[0].Err, cause) {
			t.Fatal(results)
		}
		if errors.Is(cause, io.ErrClosedPipe) && !errors.Is(e.projectionError(), cause) {
			t.Fatal("failure concealed", e.projectionError())
		}
	}
}

func TestCarrierPreservationRequiresRootBeforeEffects(t *testing.T) {
	for _, category := range []string{"xattrs", "stat"} {
		for _, subtree := range []bool{false, true} {
			destination := filepath.Join(t.TempDir(), "absent")
			e := NewExtractor(nil, destination)
			e.Xattrs = category == "xattrs"
			e.PreserveMeta = category == "stat"
			var err error
			if subtree {
				err = e.ExtractByPath("/missing", false)
			} else {
				err = e.ExtractAll()
			}
			if err == nil {
				t.Fatal("preservation succeeded without carrier")
			}
			if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("preflight changed destination", err)
			}
		}
	}
}
