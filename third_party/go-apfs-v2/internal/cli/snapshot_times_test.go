package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagesecurity"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

func TestImageTimesSnapshotRebuild(t *testing.T) {
	root, cases := imagesecurity.TimeTree(false)
	for pass := 0; pass < 2; pass++ {
		file, e := os.Create(filepath.Join(t.TempDir(), "snapshot.img"))
		if e != nil {
			t.Fatal(e)
		}
		defer file.Close()
		if e = apfswrite.CreateContainer(file, 64<<20, &apfswrite.CreateOptions{Root: root, Snapshots: []apfswrite.SnapshotSpec{{Name: "retained"}}}); e != nil {
			t.Fatal(e)
		}
		c, e := apfs.Open(file, nil)
		if e != nil {
			t.Fatal(e)
		}
		v, e := c.Volumes()
		if e != nil || len(v) != 1 {
			t.Fatal(e)
		}
		for _, tc := range cases {
			got, e := v[0].FileTimes(tc.Name)
			if e != nil {
				t.Fatal(e)
			}
			actual := [4]int64{got.Birth.UnixNano(), got.Modify.UnixNano(), got.Change.UnixNano(), got.Access.UnixNano()}
			if actual != *tc.Times {
				t.Fatalf("pass%d %s: %v != %v", pass, tc.Name, actual, *tc.Times)
			}
		}
		root, _, e = entryTreeFromVolume(v[0], nil)
		if e != nil {
			t.Fatal(e)
		}
	}
}
