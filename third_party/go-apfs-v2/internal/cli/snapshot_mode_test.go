package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

func TestImageModeSnapshotRebuild(t *testing.T) {
	root := &apfswrite.Entry{Children: []*apfswrite.Entry{
		{Name: "file", Mode: os.ModeSetuid, ModeExplicit: true, Data: []byte("payload")},
		{Name: "dir", Mode: os.ModeDir | os.ModeSticky | os.ModeSetgid, ModeExplicit: true},
		{Name: "link", Mode: os.ModeSymlink, ModeExplicit: true, Data: []byte("file")},
	}}
	for pass := 0; pass < 2; pass++ {
		file, err := os.Create(filepath.Join(t.TempDir(), "snapshot.img"))
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if err = apfswrite.CreateContainer(file, 64<<20, &apfswrite.CreateOptions{Root: root, Snapshots: []apfswrite.SnapshotSpec{{Name: "retained"}}}); err != nil {
			t.Fatal(err)
		}
		container, err := apfs.Open(file, nil)
		if err != nil {
			t.Fatal(err)
		}
		volumes, err := container.Volumes()
		if err != nil || len(volumes) != 1 {
			t.Fatal("volume count", err)
		}
		for name, want := range map[string]uint32{"file": 0104000, "dir": 043000, "link": 0120000} {
			got, err := volumes[0].Security(name)
			if err != nil || got.Source.Mode != want {
				t.Fatalf("pass %d %s: %#o != %#o: %v", pass, name, got.Source.Mode, want, err)
			}
		}
		root, _, err = entryTreeFromVolume(volumes[0], nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range root.Children {
			if !entry.ModeExplicit {
				t.Fatal("snapshot mode defaulted", entry.Name)
			}
		}
	}
}
