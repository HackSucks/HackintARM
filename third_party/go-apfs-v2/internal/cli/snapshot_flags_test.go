package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagesecurity"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

func TestImageFlagsSnapshotRebuild(t *testing.T) {
	root, cases := imagesecurity.FlagTree()
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
			got, err := v[0].BSDFlags(tc.Name)
			if err != nil {
				t.Fatal(err)
			}
			want := *tc.Flags
			if pass > 0 {
				want &^= apfs.BSDFlagCompressed
			}
			if got != want {
				t.Fatalf("pass%d %s: %#x != %#x", pass, tc.Name, got, want)
			}
			if tc.Kind == "file" {
				data, err := v[0].ReadFile(tc.Name)
				if err != nil || string(data) != "payload" {
					t.Fatal("payload", tc.Name, err)
				}
			}
		}
		root, _, e = entryTreeFromVolume(v[0], nil)
		if e != nil {
			t.Fatal(e)
		}
	}
}
