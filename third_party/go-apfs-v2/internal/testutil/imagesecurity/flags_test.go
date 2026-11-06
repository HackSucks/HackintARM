package imagesecurity_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagesecurity"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func TestImageFlagsNativeReplay(t *testing.T) {
	data, e := os.ReadFile("../../../testdata/appledouble/native/image-flags.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	z, e := gzip.NewReader(bytes.NewReader(data))
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var f imagesecurity.Fixture
	if e = json.NewDecoder(z).Decode(&f); e != nil {
		t.Fatal(e)
	}
	if len(f.Cases) != 276 || len(f.Images) != 4 || len(f.DocumentIDs) != 24 {
		t.Fatal("incomplete corpus", len(f.Cases), len(f.Images), len(f.DocumentIDs))
	}
	helpers := map[string]string{"testdata/appledouble/native/image-flags.c": f.HelperSHA256, "testdata/appledouble/native/security-copy.c": f.ParentSHA256}
	if len(f.Helpers) != 1 {
		t.Fatal("parent provenance")
	}
	for name, hash := range f.Helpers {
		helpers[name] = hash
	}
	for name, hash := range helpers {
		b, e := os.ReadFile("../../../" + name)
		if e != nil {
			t.Fatal(e)
		}
		b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
		if fmt.Sprintf("%x", sha256.Sum256(b)) != hash {
			t.Fatal("helper hash", name)
		}
	}
	if f.HFSSources["hfs_catalog.c"] != "a459793a5f38d05ad3b5a8e6f9761aefb3d9dfeb077962a7a190b6812bd37dd6" || f.HFSSources["hfs_vnops.c"] != "a07a8cd9bad0e485a6c7248facac3edcf66736727777715f8cf6a86fb77f3f44" {
		t.Fatal("HFS provenance")
	}
	native := map[string]imagesecurity.NativeCase{}
	for _, c := range f.Cases {
		key := c.Filesystem + "/" + c.Case.Name
		if _, found := native[key]; found {
			t.Fatal("duplicate", key)
		}
		native[key] = c
	}
	for _, kind := range []string{"apfs", "apfs-sensitive", "hfsx", "hfsplus"} {
		t.Run(kind, func(t *testing.T) {
			name := kind + "-flags"
			root, cases := imagesecurity.FlagTree()
			before, _ := json.Marshal(root)
			hroot := imagesecurity.HFSTree(root)
			original, _ := imagesecurity.FlagTree()
			hbefore := imagesecurity.HFSTree(original)
			file, e := os.Create(filepath.Join(t.TempDir(), "flags.img"))
			if e != nil {
				t.Fatal(e)
			}
			defer file.Close()
			var v imagesecurity.Volume
			if strings.HasPrefix(kind, "apfs") {
				if e = apfswrite.CreateContainer(file, 64<<20, &apfswrite.CreateOptions{Root: root, VolumeName: "SECURITY", CaseSensitive: kind == "apfs-sensitive", Snapshots: []apfswrite.SnapshotSpec{{Name: "flags"}}}); e != nil {
					t.Fatal(e)
				}
				c, e := apfs.Open(file, nil)
				if e != nil {
					t.Fatal(e)
				}
				vs, e := c.Volumes()
				if e != nil || len(vs) != 1 {
					t.Fatal(e)
				}
				v = vs[0]
				if count, e := vs[0].NumberOfSnapshots(); e != nil || count != 1 {
					t.Fatal(count, e)
				}
			} else {
				if e = hfsplus.CreateImage(file, 64<<20, "SECURITY", hroot, &hfsplus.CreateOptions{CaseInsensitive: kind == "hfsplus"}); e != nil {
					t.Fatal(e)
				}
				v, e = hfsplus.New(file)
				if e != nil {
					t.Fatal(e)
				}
			}
			ids := map[uint32]string{}
			for _, tc := range cases {
				t.Run(tc.Name, func(t *testing.T) {
					got, e := v.BSDFlags(tc.Name)
					if e != nil {
						t.Fatal(e)
					}
					n, ok := native[name+"/"+tc.Name]
					if !ok || n.Native.Code != 0 || n.Native.ReferenceCode != 0 || !n.Native.SameIdentity || got != *tc.Flags || n.Native.Flags != got {
						t.Fatalf("flags %#x want %#x native%+v", got, *tc.Flags, n.Native)
					}
					if got&0x40 != 0 {
						id := f.DocumentIDs[name+"/"+tc.Name]
						if (id == 0) != (!strings.HasPrefix(kind, "apfs") && tc.Kind == "symlink") {
							t.Fatal("tracked document ID missing")
						}
						old, seen := ids[id]
						if id != 0 && seen && !(old == "40-hard-a" && tc.Name == "40-hard-b") {
							t.Fatal("document ID reused", old, tc.Name)
						}
						ids[id] = tc.Name
					}
					if tc.Kind == "file" || strings.HasPrefix(tc.Kind, "hard-") {
						b, e := fs.ReadFile(v, tc.Name)
						if e != nil || string(b) != "payload" {
							t.Fatal("payload", e)
						}
					}
					if tc.Kind == "symlink" {
						link, e := v.Readlink(tc.Name)
						if e != nil || link != "target" {
							t.Fatal("link", e)
						}
					}
				})
			}
			for _, bad := range []string{"../bad", "/bad", "absent"} {
				if _, e := v.BSDFlags(bad); e == nil {
					t.Fatal("accepted", bad)
				}
			}
			after, _ := json.Marshal(root)
			if !bytes.Equal(before, after) || !reflect.DeepEqual(hbefore, hroot) {
				t.Fatal("input mutation")
			}
			hash := sha256.New()
			if _, e = file.Seek(0, 0); e != nil {
				t.Fatal(e)
			}
			if _, e = io.Copy(hash, file); e != nil {
				t.Fatal(e)
			}
			sum := fmt.Sprintf("%x", hash.Sum(nil))
			if sum != f.Images[name] {
				t.Fatal("image hash mismatch", sum, f.Images[name])
			}
			t.Logf("BSD flags image %s SHA256 %s", name, sum)
		})
	}
}
func TestImageFlagsInvalidBeforeWrite(t *testing.T) {
	for _, rootFlag := range []bool{false, true} {
		for _, hfs := range []bool{false, true} {
			for _, compressed := range []bool{false, true} {
				root := &apfswrite.Entry{Children: []*apfswrite.Entry{{Name: "file", Data: []byte("payload")}}}
				target := root.Children[0]
				if rootFlag {
					target = root
				}
				flags := uint32(0x20)
				if compressed {
					tree, _ := imagesecurity.FlagTree()
					target.Xattrs = tree.Children[len(tree.Children)-1].Xattrs
					target.Data = nil
					flags = 0
				}
				target.BSDFlags = &flags
				w := &refuseWrite{}
				var e error
				if hfs {
					e = hfsplus.CreateImage(w, 64<<20, "INVALID", imagesecurity.HFSTree(root), nil)
				} else {
					e = apfswrite.CreateContainer(w, 64<<20, &apfswrite.CreateOptions{Root: root})
				}
				// Native failure captures qualify inactive attributes with explicit
				// clear flags. These cases now reach output; active storage without
				// attributes and the existing directory restriction still fail early.
				if compressed && (!hfs || !rootFlag) {
					if !errors.Is(e, errRefuseImageWrite) || w.calls != 1 {
						t.Fatal(e, w.calls)
					}
					continue
				}
				// HFS rejects compressed directories before flag selection.
				invalid := errors.Is(e, fs.ErrInvalid) || (hfs && rootFlag && compressed && e != nil)
				if !invalid || w.calls != 0 {
					t.Fatal(e, w.calls)
				}
			}
		}
	}
	flags := uint32(0x100)
	w := &refuseWrite{}
	if e := hfsplus.CreateImage(w, 64<<20, "INVALID", &hfsplus.Entry{BSDFlags: &flags}, nil); !errors.Is(e, fs.ErrInvalid) || w.calls != 0 {
		t.Fatal(e, w.calls)
	}
	var a *apfs.Volume
	var h *hfsplus.Volume
	for _, v := range []interface{ BSDFlags(string) (uint32, error) }{a, h} {
		if _, e := v.BSDFlags("."); !errors.Is(e, fs.ErrInvalid) {
			t.Fatal(e)
		}
	}
}
func TestImageFlagsSecurityStages(t *testing.T) {
	root, _ := imagesecurity.FlagTree()
	hroot := imagesecurity.HFSTree(root)
	want := *root.BSDFlags
	source := hostdata.SecurityCopySource{UID: 501, GID: 20, Mode: 040700}
	if _, e := root.CopySecurity(root, source, hostdata.SecurityCopyOptions{Stat: true}); e != nil {
		t.Fatal(e)
	}
	if _, e := hroot.CopySecurity(hroot, source, hostdata.SecurityCopyOptions{Stat: true}); e != nil {
		t.Fatal(e)
	}
	if *root.BSDFlags != want || *hroot.BSDFlags != want {
		t.Fatal("security stage changed flags")
	}
}
