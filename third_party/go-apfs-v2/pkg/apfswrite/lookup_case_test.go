package apfswrite_test

import (
	"bytes"
	"io/fs"
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

func TestImageMetadataLookupRespectsVolumeCase(t *testing.T) {
	for _, sensitive := range []bool{false, true} {
		name := "insensitive"
		if sensitive {
			name = "sensitive"
		}
		t.Run(name, func(t *testing.T) {
			root := &apfswrite.Entry{Children: []*apfswrite.Entry{{Name: "AUX", Data: []byte("upper")}, {Name: "Nested", Mode: os.ModeDir, Children: []*apfswrite.Entry{{Name: "Ω", Data: []byte("unicode")}}}}}
			image := buildImage(t, &apfswrite.CreateOptions{Root: root, CaseSensitive: sensitive, Snapshots: []apfswrite.SnapshotSpec{{Name: "case-snapshot"}}})
			c, e := apfs.Open(bytes.NewReader(image), nil)
			if e != nil {
				t.Fatal(e)
			}
			volumes, e := c.Volumes()
			if e != nil || len(volumes) != 1 {
				t.Fatal(e)
			}
			snap, e := volumes[0].Snapshot(0)
			if e != nil {
				t.Fatal(e)
			}
			if snap.VolumeSuperblock.IncompatibleFeaturesFlags != volumes[0].Superblock.IncompatibleFeaturesFlags {
				t.Fatal("snapshot comparison profile changed")
			}
			for _, v := range volumes {
				if v.FileSystemBTree.UseCaseFolding == sensitive {
					t.Fatal("reader ignores volume feature bits")
				}
				for _, tc := range []struct{ name, want string }{{"AUX", "upper"}, {"Nested/Ω", "unicode"}} {
					b, e := fs.ReadFile(v, tc.name)
					if e != nil || string(b) != tc.want {
						t.Fatalf("%s: %q %v", tc.name, b, e)
					}
					if _, e = v.Metadata(tc.name); e != nil {
						t.Fatal(e)
					}
				}
				for _, alternate := range []string{"aux", "nested/ω"} {
					_, e := fs.ReadFile(v, alternate)
					if (e != nil) != sensitive {
						t.Fatalf("case-sensitive=%v lookup=%q error=%v", sensitive, alternate, e)
					}
				}
			}
		})
	}
}
