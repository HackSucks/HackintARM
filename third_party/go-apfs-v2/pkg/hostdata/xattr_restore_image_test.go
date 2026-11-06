package hostdata_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagesecurity"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func TestXattrRestoreImageBinding(t *testing.T) {
	for _, hfs := range []bool{false, true} {
		t.Run(fmt.Sprint(hfs), func(t *testing.T) {
			root := &apfswrite.Entry{Mode: os.ModeDir | 0755, Children: []*apfswrite.Entry{{Name: "a", Mode: 0600, LinkGroup: 1, Data: []byte("data")}, {Name: "b", Mode: 0600, LinkGroup: 1, Data: []byte("data")}, {Name: "dir", Mode: os.ModeDir | 0700}, {Name: "link", Mode: os.ModeSymlink | 0777, Data: []byte("a")}}}
			hroot := imagesecurity.HFSTree(root)
			attrs := func(i int) map[string][]byte {
				if hfs {
					if i < 0 {
						return hroot.Xattrs
					}
					return hroot.Children[i].Xattrs
				}
				if i < 0 {
					return root.Xattrs
				}
				return root.Children[i].Xattrs
			}
			restore := func(i int, name string, v []byte, o hostdata.XattrRestoreOptions) (hostdata.XattrRestoreResult, error) {
				if hfs {
					e := hroot
					if i >= 0 {
						e = hroot.Children[i]
					}
					return hroot.RestoreXattr(e, name, v, o)
				}
				e := root
				if i >= 0 {
					e = root.Children[i]
				}
				return root.RestoreXattr(e, name, v, o)
			}
			for _, i := range []int{-1, 0, 2, 3} {
				value := []byte{1, 2}
				o := hostdata.XattrRestoreOptions{Callback: func(n hostdata.XattrRestoreNotice) hostdata.CopyPipelineAction {
					if n.Event == hostdata.XattrRestoreStart {
						if _, exists := attrs(i)["ordinary"]; exists {
							t.Fatal("published before write")
						}
						return hostdata.CopyPipelineSkip
					}
					if n.Event == hostdata.XattrRestoreFinish {
						if !bytes.Equal(attrs(i)["ordinary"], value) {
							t.Fatal("not published before finish")
						}
						return hostdata.CopyPipelineQuit
					}
					return hostdata.CopyPipelineContinue
				}}
				r, e := restore(i, "ordinary", value, o)
				if !errors.Is(e, hostdata.ErrXattrRestoreCanceled) || !r.Applied || r.Completed {
					t.Fatal(r, e)
				}
				value[0] = 9
				if attrs(i)["ordinary"][0] != 1 {
					t.Fatal("value aliased caller")
				}
			}
			if !bytes.Equal(attrs(0)["ordinary"], attrs(1)["ordinary"]) {
				t.Fatal("hardlink not updated")
			}
			attrs(0)["ordinary"][0] = 7
			if attrs(1)["ordinary"][0] != 1 {
				t.Fatal("alias storage shared")
			}
			attrs(0)["ordinary"][0] = 1
			for _, i := range []int{-1, 0, 2, 3} {
				r, e := restore(i, "empty", nil, hostdata.XattrRestoreOptions{})
				if e != nil || !r.Applied {
					t.Fatal(r, e)
				}
				if _, ok := attrs(i)["empty"]; !ok {
					t.Fatal("empty removed")
				}
			}
			r, e := restore(0, "filtered#N", []byte{2}, hostdata.XattrRestoreOptions{})
			if e != nil || r.Selected || !r.Completed {
				t.Fatal(r, e)
			}
			r, e = restore(0, hostdata.SecurityName, []byte{2}, hostdata.XattrRestoreOptions{})
			if !errors.Is(e, fs.ErrPermission) || r.Applied {
				t.Fatal(r, e)
			}
			r, e = restore(0, appledouble.FinderInfoName, []byte{2}, hostdata.XattrRestoreOptions{Callback: func(hostdata.XattrRestoreNotice) hostdata.CopyPipelineAction { return hostdata.CopyPipelineContinue }})
			if e != nil || r.Applied || !r.Completed || !errors.Is(r.WriteError, fs.ErrInvalid) {
				t.Fatal(r, e)
			}
			r, e = restore(0, hostdata.ResourceForkName, []byte{3, 4}, hostdata.XattrRestoreOptions{})
			if e != nil || !r.Applied {
				t.Fatal(r, e)
			}
			// An unrelated write must preserve the fork's dedicated HFS storage.
			r, e = restore(0, "with-fork", []byte{1}, hostdata.XattrRestoreOptions{})
			if e != nil || !r.Applied {
				t.Fatal(r, e)
			}
			if hfs {
				if !bytes.Equal(hroot.Children[0].ResourceFork, []byte{3, 4}) || !bytes.Equal(hroot.Children[1].ResourceFork, []byte{3, 4}) {
					t.Fatal("HFS fork")
				}
			} else if !bytes.Equal(attrs(0)[hostdata.ResourceForkName], []byte{3, 4}) {
				t.Fatal("APFS fork")
			}
			r, e = restore(0, hostdata.ResourceForkName, nil, hostdata.XattrRestoreOptions{})
			if e != nil || !r.Applied {
				t.Fatal(r, e)
			}
			if hfs {
				if len(hroot.Children[0].ResourceFork) != 0 || len(hroot.Children[1].ResourceFork) != 0 {
					t.Fatal("fork not cleared")
				}
			} else if _, ok := attrs(0)[hostdata.ResourceForkName]; ok {
				t.Fatal("empty fork remained visible")
			}
			r, e = restore(2, hostdata.ResourceForkName, []byte{1}, hostdata.XattrRestoreOptions{})
			if !errors.Is(e, fs.ErrInvalid) || r.Applied {
				t.Fatal(r, e)
			}
			if hfs {
				hroot.Xattrs[hostdata.ResourceForkName] = []byte{1}
				_, e = restore(0, "name", nil, hostdata.XattrRestoreOptions{})
				if !errors.Is(e, fs.ErrInvalid) {
					t.Fatal(e)
				}
				delete(hroot.Xattrs, hostdata.ResourceForkName)
				hroot.Children[2].Mode = os.ModeSocket
				_, e = restore(0, "name", nil, hostdata.XattrRestoreOptions{})
				if !errors.Is(e, fs.ErrInvalid) {
					t.Fatal(e)
				}
				hroot.Children[2].Mode = os.ModeDir | 0700
				lone := &hfsplus.Entry{Mode: os.ModeDir | 0755, Children: []*hfsplus.Entry{{Name: "child", Mode: 0600, ResourceFork: []byte{1}}}}
				r, e = lone.RestoreXattr(lone.Children[0], "name", []byte{2}, hostdata.XattrRestoreOptions{})
				if e != nil || !r.Applied || len(lone.Children[0].ResourceFork) != 1 {
					t.Fatal(r, e)
				}
			}
			attrs(1)["conflict"] = []byte{1}
			r, e = restore(0, "ordinary", []byte{3}, hostdata.XattrRestoreOptions{})
			if !errors.Is(e, fs.ErrInvalid) || r.Applied {
				t.Fatal(r, e)
			}
			delete(attrs(1), "conflict")
			if hfs {
				hroot.Children = append(hroot.Children, hroot)
				_, e = hroot.RestoreXattr(hroot, "name", nil, hostdata.XattrRestoreOptions{})
			} else {
				root.Children = append(root.Children, root)
				_, e = root.RestoreXattr(root, "name", nil, hostdata.XattrRestoreOptions{})
			}
			if !errors.Is(e, fs.ErrInvalid) {
				t.Fatal(e)
			}
		})
	}
}

func TestXattrRestoreImageRoundTrip(t *testing.T) {
	for _, kind := range []string{"apfs", "apfs-sensitive", "hfsx", "hfsplus"} {
		t.Run(kind, func(t *testing.T) {
			var hashes [2]string
			for variant := range 2 {
				root := &apfswrite.Entry{Mode: os.ModeDir | 0755, Children: []*apfswrite.Entry{{Name: "a", Mode: 0600, Data: []byte("data"), LinkGroup: 1}, {Name: "b", Mode: 0600, Data: []byte("data"), LinkGroup: 1}, {Name: "dir", Mode: os.ModeDir | 0700}, {Name: "link", Mode: os.ModeSymlink | 0777, Data: []byte("a")}}}
				hroot := imagesecurity.HFSTree(root)
				hfs := kind == "hfsx" || kind == "hfsplus"
				entries := append([]*apfswrite.Entry{root}, root.Children...)
				hentries := append([]*hfsplus.Entry{hroot}, hroot.Children...)
				for i := range entries {
					for _, attr := range []appledouble.Attr{{Name: "org.example.restore", Value: []byte{0, 1, 2, 3, 4, 5, 6}}, {Name: "org.example.empty", Value: []byte{}}} {
						if variant == 0 {
							if hfs {
								if hentries[i].Xattrs == nil {
									hentries[i].Xattrs = map[string][]byte{}
								}
								hentries[i].Xattrs[attr.Name] = bytes.Clone(attr.Value)
							} else {
								if entries[i].Xattrs == nil {
									entries[i].Xattrs = map[string][]byte{}
								}
								entries[i].Xattrs[attr.Name] = bytes.Clone(attr.Value)
							}
						} else {
							// One inode write updates both regular aliases; do not partially seed them.
							if i == 2 {
								continue
							}
							var r hostdata.XattrRestoreResult
							var e error
							if hfs {
								r, e = hroot.RestoreXattr(hentries[i], attr.Name, attr.Value, hostdata.XattrRestoreOptions{})
							} else {
								r, e = root.RestoreXattr(entries[i], attr.Name, attr.Value, hostdata.XattrRestoreOptions{})
							}
							if e != nil || !r.Applied {
								t.Fatal(r, e)
							}
						}
					}
				}
				if variant == 0 {
					for _, i := range []int{1, 2} {
						if hfs {
							hentries[i].ResourceFork = []byte{7, 8, 9}
						} else {
							entries[i].Xattrs[hostdata.ResourceForkName] = []byte{7, 8, 9}
						}
					}
				} else {
					var r hostdata.XattrRestoreResult
					var e error
					if hfs {
						r, e = hroot.RestoreXattr(hentries[1], hostdata.ResourceForkName, []byte{7, 8, 9}, hostdata.XattrRestoreOptions{})
					} else {
						r, e = root.RestoreXattr(entries[1], hostdata.ResourceForkName, []byte{7, 8, 9}, hostdata.XattrRestoreOptions{})
					}
					if e != nil || !r.Applied {
						t.Fatal(r, e)
					}
				}
				file, e := os.Create(filepath.Join(t.TempDir(), "attrs.img"))
				if e != nil {
					t.Fatal(e)
				}
				defer file.Close()
				var volume imagesecurity.Volume
				if hfs {
					e = hfsplus.CreateImage(file, 64<<20, "RESTORE", hroot, &hfsplus.CreateOptions{CaseInsensitive: kind == "hfsplus"})
					if e == nil {
						volume, e = hfsplus.New(file)
					}
				} else {
					e = apfswrite.CreateContainer(file, 64<<20, &apfswrite.CreateOptions{Root: root, VolumeName: "RESTORE", CaseSensitive: kind == "apfs-sensitive", Snapshots: []apfswrite.SnapshotSpec{{Name: "attrs"}}})
					if e == nil {
						var c *apfs.Container
						c, e = apfs.Open(file, nil)
						if e == nil {
							vs, err := c.Volumes()
							e = err
							if e == nil && len(vs) == 1 {
								volume = vs[0]
							} else if e == nil {
								t.Fatal("volume count")
							}
						}
					}
				}
				if e != nil {
					t.Fatal(e)
				}
				for _, path := range []string{".", "a", "b", "dir", "link"} {
					attrs, e := volume.Xattrs(path)
					if e != nil {
						t.Fatal(e)
					}
					if (path == "a" || path == "b") && !bytes.Equal(attrs[hostdata.ResourceForkName], []byte{7, 8, 9}) {
						t.Fatal("resource fork readback", path, attrs)
					}
					v, ok := attrs["org.example.empty"]
					if !ok || len(v) != 0 || !bytes.Equal(attrs["org.example.restore"], []byte{0, 1, 2, 3, 4, 5, 6}) {
						t.Fatal(path, attrs)
					}
				}
				if _, e = file.Seek(0, io.SeekStart); e != nil {
					t.Fatal(e)
				}
				hash := sha256.New()
				if _, e = io.Copy(hash, file); e != nil {
					t.Fatal(e)
				}
				hashes[variant] = fmt.Sprintf("%x", hash.Sum(nil))
			}
			if hashes[0] != hashes[1] {
				t.Fatal("image bytes changed", hashes)
			}
			t.Logf("xattr restoration image %s SHA256 %s", kind, hashes[0])
		})
	}
}
