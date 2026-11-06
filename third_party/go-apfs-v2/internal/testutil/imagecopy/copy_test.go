package imagecopy_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagecopy"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagerestore"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagesecurity"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func metadata(t *testing.T, v imagesecurity.Volume, name string) imagerestore.Metadata {
	t.Helper()
	s, e := v.Security(name)
	if e != nil {
		t.Fatal(e)
	}
	security := s.Source.Properties.RawSecurity
	if security == nil {
		security = &appledouble.FileSecurity{}
	}
	b, e := security.MarshalDarwinBinary()
	if e != nil {
		t.Fatal(e)
	}
	return imagerestore.Metadata{Security: hex.EncodeToString(b), UID: s.Source.UID, GID: s.Source.GID, Mode: s.Source.Mode}
}
func inode(t *testing.T, v imagesecurity.Volume, name string) uint64 {
	t.Helper()
	info, e := fs.Stat(v, name)
	if e != nil {
		t.Fatal(e)
	}
	switch n := info.Sys().(type) {
	case *apfs.Inode:
		return n.Identifier
	case *hfsplus.HFSPlusCatalogFile:
		return uint64(n.FileID)
	case *hfsplus.HFSPlusCatalogFolder:
		return uint64(n.FolderID)
	}
	t.Fatal("missing inode")
	return 0
}
func TestImageSecurityCopyNativeReplay(t *testing.T) {
	b, e := os.ReadFile("../../../testdata/appledouble/native/image-security-copy.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	z, e := gzip.NewReader(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var fixture imagecopy.Fixture
	if e = json.NewDecoder(z).Decode(&fixture); e != nil {
		t.Fatal(e)
	}
	if len(fixture.Cases) != 2692 || len(fixture.InitialImages) != 8 || len(fixture.NativeImages) != 8 || len(fixture.FinalImages) != 8 || len(fixture.Aliases) != 1344 {
		t.Fatal("incomplete native corpus")
	}
	for path, want := range fixture.Helpers {
		b, e := os.ReadFile("../../../" + path)
		if e != nil {
			t.Fatal(e)
		}
		b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
		if fmt.Sprintf("%x", sha256.Sum256(b)) != want {
			t.Fatal("helper provenance", path)
		}
	}
	observed := map[string]imagecopy.NativeCase{}
	for _, n := range fixture.Cases {
		key := n.Filesystem + "/" + n.Case.Name
		if _, ok := observed[key]; ok {
			t.Fatal("duplicate case")
		}
		observed[key] = n
	}
	for _, kind := range []string{"apfs", "apfs-sensitive", "hfsx", "hfsplus"} {
		for _, scene := range imagecopy.Trees(fixture.ActorUID, fixture.ActorGID) {
			name := kind + "-" + scene.Name
			t.Run(name, func(t *testing.T) {
				hfsTree := imagesecurity.HFSTree(scene.Root)
				create := func(label, want string) imagesecurity.Volume {
					file, e := os.Create(filepath.Join(t.TempDir(), label+".img"))
					if e != nil {
						t.Fatal(e)
					}
					t.Cleanup(func() { file.Close() })
					var volume imagesecurity.Volume
					if strings.HasPrefix(kind, "apfs") {
						if e = apfswrite.CreateContainer(file, 64<<20, &apfswrite.CreateOptions{Root: scene.Root, VolumeName: "COPY", CaseSensitive: kind == "apfs-sensitive"}); e != nil {
							t.Fatal(e)
						}
						c, e := apfs.Open(file, nil)
						if e != nil {
							t.Fatal(e)
						}
						v, e := c.Volumes()
						if e != nil || len(v) != 1 {
							t.Fatal("volume count", e)
						}
						volume = v[0]
					} else {
						if e = hfsplus.CreateImage(file, 64<<20, "COPY", hfsTree, &hfsplus.CreateOptions{CaseInsensitive: kind == "hfsplus"}); e != nil {
							t.Fatal(e)
						}
						volume, e = hfsplus.New(file)
						if e != nil {
							t.Fatal(e)
						}
					}
					if _, e = file.Seek(0, 0); e != nil {
						t.Fatal(e)
					}
					hash := sha256.New()
					if _, e = io.Copy(hash, file); e != nil {
						t.Fatal(e)
					}
					if got := fmt.Sprintf("%x", hash.Sum(nil)); got != want {
						t.Fatalf("%s native image hash %s != %s", label, got, want)
					}
					return volume
				}
				before := create("before", fixture.InitialImages[name])
				for _, c := range scene.Cases {
					n, ok := observed[name+"/"+c.Name]
					if !ok || !sameJSON(n.Case, c) {
						t.Fatal("missing native case", c.Name)
					}
					if got := metadata(t, before, c.Target); got != n.Native.Before {
						t.Fatalf("initial metadata %s: %+v != %+v", c.Name, got, n.Native.Before)
					}
					var result hostdata.SecurityCopyResult
					var err error
					if strings.HasPrefix(kind, "apfs") {
						result, err = imagecopy.ApplyAPFS(scene.Root, c)
					} else {
						result, err = imagecopy.ApplyHFS(hfsTree, c)
					}
					gotError := ""
					if err != nil {
						gotError = err.Error()
					}
					if gotError != n.GoError || !sameJSON(imagecopy.NativeCase{GoResult: result}, imagecopy.NativeCase{GoResult: n.GoResult}) {
						t.Fatal("restoration result", c.Name, result, err)
					}
				}
				after := create("after", fixture.FinalImages[name])
				for _, c := range scene.Cases {
					t.Run(c.Name, func(t *testing.T) {
						n := observed[name+"/"+c.Name]
						native, written := n.Native, n.Written
						if (n.GoError == "" && (native.Code != 0 || native.Errno != 0)) || (n.GoError != "" && (native.Code != -1 || native.Errno != 22 || n.GoResult.Completed || n.GoResult.Writes != 0)) || written.Code != 0 || written.Errno != 0 || !native.SameIdentity || !written.SameIdentity || native.After != written.After || native.AfterAttributes != written.AfterAttributes {
							t.Fatal("native write comparison")
						}
						got := metadata(t, after, c.Target)
						if got != native.After {
							t.Fatalf("final metadata: %+v != %+v", got, native.After)
						}
						if got.UID != native.Before.UID || got.GID != native.Before.GID {
							t.Fatal("numeric metadata changed")
						}
						attrs, e := after.Xattrs(c.Target)
						if e != nil {
							t.Fatal(e)
						}
						original, e := before.Xattrs(c.Target)
						if e != nil {
							t.Fatal(e)
						}
						if !bytes.Equal(attrs["user.unrelated"], original["user.unrelated"]) {
							t.Fatal("unrelated attribute changed")
						}
						if (n.GoError != "" || !c.Options.ACL) && !reflect.DeepEqual(attrs, original) {
							t.Fatal("no-op changed raw storage")
						}
						if inode(t, after, c.Target) != written.Inode {
							t.Fatal("written inode mismatch")
						}
						for _, alias := range c.Aliases {
							a, ok := fixture.Aliases[name+"/native/"+alias]
							if !ok || a.After != native.After || a.Inode != native.Inode {
								t.Fatal("native alias mismatch")
							}
							w, ok := fixture.Aliases[name+"/written/"+alias]
							if !ok || w.After != written.After || w.Inode != written.Inode || inode(t, after, alias) != written.Inode || metadata(t, after, alias) != got {
								t.Fatal("written alias mismatch")
							}
						}
						for _, v := range []imagesecurity.Volume{before, after} {
							info, e := fs.Stat(v, c.Target)
							if e != nil {
								t.Fatal(e)
							}
							if info.Mode()&os.ModeSymlink != 0 {
								target, e := v.Readlink(c.Target)
								if e != nil || target != "missing-target" {
									t.Fatal("symlink changed", e)
								}
							} else if info.Mode().IsRegular() {
								data, e := fs.ReadFile(v, c.Target)
								if e != nil || string(data) != "payload" {
									t.Fatal("payload changed", e)
								}
							}
						}
					})
				}
			})
		}
	}
}

func sameJSON(a, b any) bool {
	left, e := json.Marshal(a)
	if e != nil {
		return false
	}
	right, e := json.Marshal(b)
	return e == nil && bytes.Equal(left, right)
}
