package hostwalk

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/fidelity"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func TestCarrierNativeValueWalk(t *testing.T) {
	for _, name := range []string{"disabled", "error", "keep", "drop", "compressed", "decompress-fork", "decompress-inline", "bad-header", "reject-compression"} {
		t.Run(name, func(t *testing.T) {
			attrs := map[string]appledouble.Value{"ordinary": bytes.NewReader([]byte{1}), hostdata.ResourceForkName: bytes.NewReader([]byte("fork")), hostdata.SecurityName: bytes.NewReader(nil)}
			opts := &Options{Xattrs: true, Compression: true, owner: &treeOwner{ctx: context.Background()}, KeepName: func(string) bool { return true }}
			opts.CaptureLimits = &hostdata.XattrCaptureLimits{ValueBytes: 1}
			opts.nativeValues = func(context.Context, *os.Root, string, hostdata.XattrCaptureLimits) (map[string]appledouble.Value, error) {
				if name == "error" {
					return nil, io.ErrClosedPipe
				}
				return attrs, nil
			}
			switch name {
			case "disabled":
				opts.Xattrs = false
			case "drop":
				opts.KeepName = nil
			case "compressed", "decompress-fork", "reject-compression":
				attrs[hostdata.DecmpfsName] = bytes.NewReader(compressionHeader(4))
			case "decompress-inline":
				attrs[hostdata.DecmpfsName] = bytes.NewReader(compressionHeader(3))
			case "bad-header":
				attrs[hostdata.DecmpfsName] = bytes.NewReader([]byte{1})
			}
			if name == "decompress-fork" || name == "decompress-inline" {
				opts.Compression = false
			}
			if name == "reject-compression" {
				opts.KeepName = func(s string) bool { return s != hostdata.DecmpfsName }
			}
			w := &walker[*carrierNode]{opts: opts, report: &fidelity.Report{}}
			got, compressed, e := w.collectValueXattrs("file", true)
			if name == "error" || name == "bad-header" {
				if e == nil {
					t.Fatal("missing error")
				}
				if name == "error" && !errors.Is(e, io.ErrClosedPipe) {
					t.Fatal(e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if compressed != (name == "compressed") {
				t.Fatal("compression", compressed)
			}
			if name == "disabled" {
				if got != nil {
					t.Fatal(got)
				}
				return
			}
			if name == "drop" {
				if len(got) != 0 || w.report.Count(fidelity.Xattr) != 1 || w.report.Count(fidelity.ResourceFork) != 1 || w.report.Count(fidelity.ACL) != 1 {
					t.Fatal(got, w.report)
				}
				return
			}
			_, fork := got[hostdata.ResourceForkName]
			if fork != (name != "decompress-fork" && name != "reject-compression") {
				t.Fatal("resource fork", name, got)
			}
		})
	}
}
