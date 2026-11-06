//go:build darwin

package hostwalk

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func TestCarrierNativeInactiveCompressionFiles(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, preserve := range []bool{false, true} {
			t.Run(fmt.Sprintf("stream-%t-preserve-%t", stream, preserve), func(t *testing.T) {
				root := t.TempDir()
				path := filepath.Join(root, "file")
				want := []byte("ordinary contents")
				f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = f.Write(want); e != nil {
					f.Close()
					t.Fatal(e)
				}
				attrs := map[string][]byte{hostdata.DecmpfsName: []byte("stale"), hostdata.ResourceForkName: []byte("retained fork")}
				for name, value := range attrs {
					if e = hostdata.SetXattr(f, name, value); e != nil {
						f.Close()
						t.Fatal(e)
					}
				}
				if e = f.Close(); e != nil {
					t.Fatal(e)
				}
				opts := &Options{Context: t.Context(), Xattrs: true, Compression: preserve, Keep: func(string, []byte) bool { return true }, KeepName: func(string) bool { return true }}
				var tree *carrierNode
				if stream {
					owned, e := OpenWalk(root, opts, makeCarrierNode)
					if e != nil {
						t.Fatal(e)
					}
					defer owned.Close()
					tree = owned.Root
				} else {
					var e error
					tree, _, e = Walk(root, opts, makeCarrierNode)
					if e != nil {
						t.Fatal(e)
					}
				}
				n := tree.Children[0]
				if n.BSDFlags == nil || *n.BSDFlags != 0 {
					t.Fatal("missing explicit inactive flags", n.BSDFlags)
				}
				data := n.Data
				if stream {
					if n.DataValue == nil {
						t.Fatal("ordinary data lost")
					}
					data, e = io.ReadAll(io.NewSectionReader(n.DataValue, 0, n.DataValue.Size()))
					if e != nil {
						t.Fatal(e)
					}
				}
				if !bytes.Equal(data, want) {
					t.Fatal("data changed", string(data))
				}
				for name, want := range attrs {
					got := n.Xattrs[name]
					if stream {
						v := n.XattrValues[name]
						if v == nil {
							t.Fatal("inactive metadata lost", name)
						}
						got, e = io.ReadAll(io.NewSectionReader(v, 0, v.Size()))
						if e != nil {
							t.Fatal(e)
						}
					}
					if !bytes.Equal(got, want) {
						t.Fatal("metadata changed", name)
					}
				}
			})
		}
	}
}
