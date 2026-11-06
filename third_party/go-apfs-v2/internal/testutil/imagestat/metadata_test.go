package imagestat_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagesecurity"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagestat"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// Reuse the independently mounted/read native stat corpus and reproduce its image
// hashes. The combined API must return those native values without host capture.
func TestImageMetadataNativeReplay(t *testing.T) {
	f := fixture(t)
	native := map[string]imagesecurity.NativeCase{}
	for _, c := range f.Cases {
		native[c.Filesystem+"/"+c.Case.Name] = c
	}
	for _, kind := range []string{"apfs", "apfs-sensitive", "hfsplus", "hfsx"} {
		t.Run(kind, func(t *testing.T) {
			root, hroot, cases, e := imagestat.Build(f.StatModels, strings.HasPrefix(kind, "hfs"))
			if e != nil {
				t.Fatal(e)
			}
			file, e := os.Create(filepath.Join(t.TempDir(), "metadata.img"))
			if e != nil {
				t.Fatal(e)
			}
			defer file.Close()
			var v hostdata.ImageMetadataFS
			if strings.HasPrefix(kind, "hfs") {
				if e = hfsplus.CreateImage(file, 64<<20, "SECURITY", hroot, &hfsplus.CreateOptions{CaseInsensitive: kind == "hfsplus"}); e != nil {
					t.Fatal(e)
				}
				v, e = hfsplus.New(file)
				if e != nil {
					t.Fatal(e)
				}
			} else {
				if e = apfswrite.CreateContainer(file, 64<<20, &apfswrite.CreateOptions{Root: root, VolumeName: "SECURITY", CaseSensitive: kind == "apfs-sensitive", Snapshots: []apfswrite.SnapshotSpec{{Name: "stat"}}}); e != nil {
					t.Fatal(e)
				}
				c, e := apfs.Open(file, nil)
				if e != nil {
					t.Fatal(e)
				}
				volumes, e := c.Volumes()
				if e != nil || len(volumes) != 1 {
					t.Fatal(e)
				}
				v = volumes[0]
			}
			identities := map[string]uint64{}
			for _, tc := range cases {
				got, e := v.Metadata(tc.Name)
				if e != nil {
					t.Fatal(tc.Name, e)
				}
				n, ok := native[kind+"-stat/"+tc.Name]
				if !ok || n.Native.Code != 0 || n.Native.ReferenceCode != 0 || !n.Native.SameIdentity {
					t.Fatal("missing native observation")
				}
				if got.UID != n.Native.UID || got.GID != n.Native.GID || got.Mode != n.Native.Mode || got.BSDFlags != n.Native.Flags || got.LinkID != n.Native.Inode || got.Times == nil {
					t.Fatalf("%s: %+v != %+v", tc.Name, got, n.Native)
				}
				times := [4]int64{got.Times.Birth.UnixNano(), got.Times.Modify.UnixNano(), got.Times.Change.UnixNano(), got.Times.Access.UnixNano()}
				if times != n.Native.Times {
					t.Fatalf("%s: times %v != %v", tc.Name, times, n.Native.Times)
				}
				identities[tc.Name] = got.LinkID
				got.Times.Birth = got.Times.Access
				again, e := v.Metadata(tc.Name)
				if e != nil || again.Times.Birth.UnixNano() != n.Native.Times[0] {
					t.Fatal("aliased timestamp storage", e)
				}
			}
			for name, id := range identities {
				if strings.HasSuffix(name, "-hard-a") && identities[strings.TrimSuffix(name, "a")+"b"] != id {
					t.Fatal("hardlink identity lost")
				}
			}
			for _, name := range []string{"", "/", "../escape", "missing"} {
				got, e := v.Metadata(name)
				var pe *fs.PathError
				if !errors.As(e, &pe) || pe.Op != "metadata" || got != (hostdata.ImageMetadata{}) {
					t.Fatalf("%q: %+v %v", name, got, e)
				}
			}
			if _, e = file.Seek(0, 0); e != nil {
				t.Fatal(e)
			}
			hash := sha256.New()
			if _, e = io.Copy(hash, file); e != nil {
				t.Fatal(e)
			}
			if fmt.Sprintf("%x", hash.Sum(nil)) != f.Images[kind+"-stat"] {
				t.Fatal("native image hash mismatch")
			}
		})
	}
}
