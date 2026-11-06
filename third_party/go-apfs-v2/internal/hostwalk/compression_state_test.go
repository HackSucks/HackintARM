package hostwalk

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/fidelity"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

func TestCarrierInactiveCompression(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, preserve := range []bool{false, true} {
			for _, header := range [][]byte{compressionHeader(4), []byte("stale"), {}} {
				t.Run(fmt.Sprintf("stream-%t-preserve-%t-header-%d", stream, preserve, len(header)), func(t *testing.T) {
					p, m, s := carrierFixture(t)
					record := carrierFile(t, p, "file", "file")
					flags := uint32(0x8000)
					record.Darwin.Flags = &flags
					values := map[string][]byte{hostdata.DecmpfsName: header, hostdata.ResourceForkName: []byte("retained fork")}
					record.Attributes = attrsCarrier(t, s, values)
					commitCarrier(t, s, []metatransport.Record{record})
					// Inactive metadata never replaces a subsequently edited ordinary payload.
					want := []byte("WXYZ edited ordinary data")
					if e := os.WriteFile(filepath.Join(p, "file"), want, 0600); e != nil {
						t.Fatal(e)
					}
					opts := &Options{Context: t.Context(), MetadataRoot: m, Compression: preserve, Keep: func(string, []byte) bool { return true }, KeepName: func(string) bool { return true }}
					var got *carrierNode
					var report *fidelity.Report
					if stream {
						tree, e := OpenWalk(p, opts, makeCarrierNode)
						if e != nil {
							t.Fatal(e)
						}
						defer tree.Close()
						got, report = tree.Root, tree.Report
					} else {
						var e error
						got, report, e = Walk(p, opts, makeCarrierNode)
						if e != nil {
							t.Fatal(e)
						}
					}
					n := got.Children[0]
					if n.BSDFlags == nil || *n.BSDFlags != flags || report.Count(fidelity.Compression) != 0 {
						t.Fatal(n.BSDFlags, report)
					}
					data := n.Data
					if stream {
						if n.DataValue == nil {
							t.Fatal("ordinary data source lost")
						}
						var e error
						data, e = io.ReadAll(io.NewSectionReader(n.DataValue, 0, n.DataValue.Size()))
						if e != nil {
							t.Fatal(e)
						}
					}
					if !bytes.Equal(data, want) {
						t.Fatal("ordinary payload replaced", string(data))
					}
					for name, want := range values {
						data := n.Xattrs[name]
						if stream {
							value := n.XattrValues[name]
							if value == nil {
								t.Fatal("attribute lost", name)
							}
							var e error
							data, e = io.ReadAll(io.NewSectionReader(value, 0, value.Size()))
							if e != nil {
								t.Fatal(e)
							}
						}
						if !bytes.Equal(data, want) {
							t.Fatal("inactive attribute changed", name)
						}
					}
				})
			}
		}
	}
}
func TestCarrierNativeInactiveCompressionValues(t *testing.T) {
	for _, preserve := range []bool{false, true} {
		attrs := map[string]appledouble.Value{hostdata.DecmpfsName: bytes.NewReader([]byte("not a header")), hostdata.ResourceForkName: bytes.NewReader([]byte("fork"))}
		opts := &Options{Xattrs: true, Compression: preserve, owner: &treeOwner{ctx: t.Context()}, KeepName: func(string) bool { return true }}
		opts.nativeValues = func(context.Context, *os.Root, string, hostdata.XattrCaptureLimits) (map[string]appledouble.Value, error) {
			return attrs, nil
		}
		w := &walker[*carrierNode]{opts: opts, report: &fidelity.Report{}}
		got, compressed, e := w.collectValueXattrs("file", false)
		if e != nil || compressed || len(got) != 2 {
			t.Fatal(got, compressed, e)
		}
	}
}
