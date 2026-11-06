package imagesecurity_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagesecurity"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/securitycopy"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
)

func TestImageModeNativeReplay(t *testing.T) {
	const corpus = "../../../testdata/appledouble/native/image-mode-security.json.gz"
	b, err := os.ReadFile(corpus)
	if err != nil {
		t.Fatal(err)
	}
	z, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var fixture imagesecurity.Fixture
	if err = json.NewDecoder(z).Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 656 || len(fixture.Images) != 16 || len(fixture.NativeAccess) != 512 {
		t.Fatal("incomplete mode corpus")
	}
	for name, want := range map[string]string{"image-security.c": fixture.HelperSHA256, "security-copy.c": fixture.ParentSHA256} {
		b, err := os.ReadFile("../../../testdata/appledouble/native/" + name)
		if err != nil {
			t.Fatal(err)
		}
		b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
		if fmt.Sprintf("%x", sha256.Sum256(b)) != want {
			t.Fatal("helper provenance", name)
		}
	}
	observed := map[string]imagesecurity.NativeCase{}
	for _, n := range fixture.Cases {
		key := n.Filesystem + "/" + n.Case.Name
		if _, ok := observed[key]; ok {
			t.Fatal("duplicate native mode case", key)
		}
		observed[key] = n
	}
	for _, kind := range []string{"apfs", "apfs-sensitive", "hfsx", "hfsplus"} {
		for _, scene := range imagesecurity.Modes(fixture.ActorUID, fixture.ActorGID) {
			t.Run(kind+"-"+scene.Name, func(t *testing.T) {
				file, err := os.Create(filepath.Join(t.TempDir(), "mode.img"))
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				before, err := json.Marshal(scene.Root)
				if err != nil {
					t.Fatal(err)
				}
				var volume imagesecurity.Volume
				if strings.HasPrefix(kind, "apfs") {
					err = apfswrite.CreateContainer(file, 64<<20, &apfswrite.CreateOptions{Root: scene.Root, VolumeName: "SECURITY", CaseSensitive: kind == "apfs-sensitive"})
					if err != nil {
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
					volume = volumes[0]
				} else {
					hfsTree := imagesecurity.HFSTree(scene.Root)
					err = hfsplus.CreateImage(file, 64<<20, "SECURITY", hfsTree, &hfsplus.CreateOptions{CaseInsensitive: kind == "hfsplus"})
					if err != nil {
						t.Fatal(err)
					}
					volume, err = hfsplus.New(file)
					if err != nil {
						t.Fatal(err)
					}
				}
				after, err := json.Marshal(scene.Root)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("input modified", err)
				}
				if _, err = file.Seek(0, 0); err != nil {
					t.Fatal(err)
				}
				hash := sha256.New()
				if _, err = io.Copy(hash, file); err != nil {
					t.Fatal(err)
				}
				if got := fmt.Sprintf("%x", hash.Sum(nil)); got != fixture.Images[kind+"-"+scene.Name] {
					t.Fatal("native image hash mismatch", got)
				}
				ids := map[string]uint64{}
				for _, tc := range scene.Cases {
					t.Run(tc.Name, func(t *testing.T) {
						n, ok := observed[kind+"-"+scene.Name+"/"+tc.Name]
						if !ok || n.Case != tc {
							t.Fatal("missing native case", tc)
						}
						got, err := volume.Security(tc.Name)
						if err != nil {
							t.Fatal(err)
						}
						if got.Source.Mode != uint32(tc.Mode) || got.Source.UID != tc.UID || got.Source.GID != tc.GID || got.Disposition != tc.Disposition {
							t.Fatalf("metadata: %+v != %+v", got, tc)
						}
						if n.Native.Code != 0 || n.Native.Errno != 0 || n.Native.ReferenceCode != 0 || n.Native.ReferenceErrno != 0 || !n.Native.SameIdentity || n.Native.Mode != uint32(tc.Mode) || !reflect.DeepEqual(n.Native.Properties, n.Native.ReferenceProperties) || !reflect.DeepEqual(securitycopy.PropertiesFromGo(got.Source.Properties), n.Native.Properties) {
							t.Fatal("native mode/properties mismatch")
						}
						info, err := fs.Stat(volume, tc.Name)
						if err != nil {
							t.Fatal(err)
						}
						want := os.FileMode(tc.Mode & 0777)
						if tc.Mode&04000 != 0 {
							want |= os.ModeSetuid
						}
						if tc.Mode&02000 != 0 {
							want |= os.ModeSetgid
						}
						if tc.Mode&01000 != 0 {
							want |= os.ModeSticky
						}
						if tc.Kind == "directory" {
							want |= os.ModeDir
						}
						if tc.Kind == "symlink" {
							want |= os.ModeSymlink
						}
						if info.Mode() != want {
							t.Fatalf("FileInfo mode %s != %s", info.Mode(), want)
						}
						var inode uint64
						switch s := info.Sys().(type) {
						case *apfs.Inode:
							inode = s.Identifier
						case *hfsplus.HFSPlusCatalogFile:
							inode = uint64(s.FileID)
						case *hfsplus.HFSPlusCatalogFolder:
							inode = uint64(s.FolderID)
						default:
							t.Fatal("inode metadata")
						}
						if inode != n.Native.Inode {
							t.Fatal("native inode mismatch")
						}
						ids[tc.Name] = inode
						if tc.Kind == "hard-b" && ids[strings.TrimSuffix(tc.Name, "hard-b")+"hard-a"] != inode {
							t.Fatal("hard-link identity diverged")
						}
						if tc.Kind == "symlink" {
							wantAccess := "readlink:missing-target"
							if tc.Mode&0400 == 0 {
								wantAccess = "readlink:errno13"
							}
							if fixture.NativeAccess[kind+"-"+scene.Name+"/"+tc.Name] != wantAccess {
								t.Fatal("native readlink result")
							}
							if target, err := volume.Readlink(tc.Name); err != nil || target != "missing-target" {
								t.Fatal("symlink payload", target, err)
							}
						} else if tc.Kind == "file" || strings.HasPrefix(tc.Kind, "hard-") {
							wantAccess := "read:7061796c6f6164"
							if tc.Mode&0400 == 0 {
								wantAccess = "read:errno13"
							}
							if fixture.NativeAccess[kind+"-"+scene.Name+"/"+tc.Name] != wantAccess {
								t.Fatal("native read result")
							}
							if data, err := fs.ReadFile(volume, tc.Name); err != nil || string(data) != "payload" {
								t.Fatal("file payload", err)
							}
						}
						attrs, err := volume.Xattrs(tc.Name)
						if err != nil {
							t.Fatal(err)
						}
						if tc.Name != "." && string(attrs["user.mode"]) != "retained" {
							t.Fatal("unrelated attribute changed")
						}
					})
				}
			})
		}
	}
}
