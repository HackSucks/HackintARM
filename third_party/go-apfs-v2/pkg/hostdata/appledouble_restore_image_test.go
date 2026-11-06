package hostdata_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagesecurity"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

// This is a fixture provider for a known visible namespace, not a general image
// transport. Production image APIs perform xattr/ACL/stat staging; quarantine
// uses the existing planner and a captured macOS 26 absent-process context.
type unpackImageBackend struct {
	hostdata.UnpackBackend
	attrs  func() map[string][]byte
	remove func(string)
	write  func(string, []byte) error
	acl    func(appledouble.ACLUpdate) error
	stat   func(bool) error
	order  []string
}

func (b *unpackImageBackend) ListXattrSize() (int, error) {
	b.order = append(b.order, "size")
	size := 0
	for n := range b.attrs() {
		size += len(n) + 1
	}
	return size, nil
}
func (b *unpackImageBackend) XattrNames(int) ([]string, error) {
	b.order = append(b.order, "names")
	var names []string
	for n := range b.attrs() {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}
func (b *unpackImageBackend) RemoveXattr(n string) error {
	b.order = append(b.order, "remove:"+n)
	b.remove(n)
	return nil
}
func (b *unpackImageBackend) WriteXattr(n string, v []byte) error {
	b.order = append(b.order, "write:"+n)
	return b.write(n, v)
}
func (b *unpackImageBackend) CaptureForkState() (hostdata.UnpackForkState, error) {
	b.order = append(b.order, "fork-stat")
	return hostdata.UnpackForkState{}, nil
}
func (b *unpackImageBackend) Quarantine(v []byte) hostdata.CopyStageResult {
	b.order = append(b.order, "quarantine")
	f := appledouble.File{Attrs: []appledouble.Attr{{Name: appledouble.QuarantineName, Value: v}}}
	updates, e := f.QuarantineUpdates(appledouble.QuarantineMacOS26, nil)
	if e == nil && updates[0].Quarantine != nil {
		var plan *appledouble.QuarantineApplication
		plan, e = updates[0].Quarantine.PlanApplication(appledouble.QuarantineApplicationContext{Profile: appledouble.QuarantineMacOS26, Process: &appledouble.QuarantineProcess{Absent: true}, ExistingXattr: b.attrs()[appledouble.QuarantineName], Timestamp: 1700000040})
		if e == nil && plan.Write {
			e = b.write(appledouble.QuarantineName, plan.Value)
		}
	}
	if e != nil {
		return hostdata.CopyStageResult{Code: -1, Err: e}
	}
	return hostdata.CopyStageResult{}
}
func (b *unpackImageBackend) ACL(v []byte) hostdata.CopyStageResult {
	b.order = append(b.order, "acl")
	f := appledouble.File{Attrs: []appledouble.Attr{{Name: appledouble.ACLTextName, Value: v}}}
	u, e := f.ACLUpdate(nil)
	if e == nil {
		e = b.acl(u)
	}
	if e != nil {
		return hostdata.CopyStageResult{Code: -1, Err: e}
	}
	return hostdata.CopyStageResult{}
}
func (b *unpackImageBackend) Stat(hidden bool) hostdata.CopyStageResult {
	b.order = append(b.order, "stat")
	if e := b.stat(hidden); e != nil {
		return hostdata.CopyStageResult{Code: -1, Err: e}
	}
	return hostdata.CopyStageResult{}
}

func TestUnpackRestoreImageComposition(t *testing.T) {
	acl := &appledouble.ACL{Entries: []appledouble.ACLEntry{{Principal: [16]byte{1}, Flags: 1, Rights: 1}}}
	text, e := acl.MarshalText()
	if e != nil {
		t.Fatal(e)
	}
	q := &appledouble.Quarantine{Flags: 1, Timestamp: 123, Agent: "capture"}
	qbytes, e := q.MarshalBinaryWithProfile(appledouble.QuarantineMacOS26)
	if e != nil {
		t.Fatal(e)
	}
	metadata := appledouble.File{FinderInfo: [32]byte{0: 1, 8: 0x40}, ResourceFork: []byte{7, 8, 9}, Attrs: []appledouble.Attr{{Name: appledouble.ACLTextName, Value: []byte("malformed earlier")}, {Name: appledouble.ACLTextName, Value: text}, {Name: appledouble.ACLTextName}, {Name: appledouble.QuarantineName, Value: qbytes}, {Name: "ordinary", Value: []byte{1, 2}}, {Name: "skip#N", Value: []byte{3}}}}
	data := unpackData(t, metadata)
	for _, kind := range []string{"apfs", "apfs-sensitive", "hfsx", "hfsplus"} {
		t.Run(kind, func(t *testing.T) {
			var hashes [2]string
			for variant := range 2 {
				times := hostdata.FileTimes{Birth: time.Unix(1700000000, 0), Modify: time.Unix(1700000001, 0), Change: time.Unix(1700000002, 0), Access: time.Unix(1700000003, 0)}
				old := map[string][]byte{"user.stale": []byte("old"), "skip#N": []byte("must be removed before filtering")}
				root := &apfswrite.Entry{Mode: os.ModeDir | 0755, Times: &times, Children: []*apfswrite.Entry{{Name: "a", Mode: 0600, UID: 501, GID: 20, Times: &times, LinkGroup: 1, Data: []byte("payload"), Xattrs: maps.Clone(old)}, {Name: "b", Mode: 0600, UID: 501, GID: 20, Times: &times, LinkGroup: 1, Data: []byte("payload"), Xattrs: maps.Clone(old)}}}
				hroot := imagesecurity.HFSTree(root)
				hfs := kind == "hfsx" || kind == "hfsplus"
				source := hostdata.StatCopySource{UID: 501, GID: 20, Mode: 0100640, Times: hostdata.FileTimes{Modify: time.Unix(1700000100, 0), Access: time.Unix(1700000200, 0)}}
				b := &unpackImageBackend{}
				b.attrs = func() map[string][]byte {
					if hfs {
						return hroot.Children[0].Xattrs
					}
					return root.Children[0].Xattrs
				}
				b.remove = func(n string) {
					if hfs {
						for _, a := range hroot.Children {
							delete(a.Xattrs, n)
						}
					} else {
						for _, a := range root.Children {
							delete(a.Xattrs, n)
						}
					}
				}
				b.write = func(n string, v []byte) error {
					if n == appledouble.QuarantineName {
						if hfs {
							for _, a := range hroot.Children {
								a.Xattrs[n] = bytes.Clone(v)
							}
						} else {
							for _, a := range root.Children {
								a.Xattrs[n] = bytes.Clone(v)
							}
						}
						return nil
					}
					var r hostdata.XattrRestoreResult
					var e error
					if hfs {
						r, e = hroot.RestoreXattr(hroot.Children[0], n, v, hostdata.XattrRestoreOptions{})
					} else {
						r, e = root.RestoreXattr(root.Children[0], n, v, hostdata.XattrRestoreOptions{})
					}
					if e == nil && !r.Applied {
						return fmt.Errorf("xattr not applied: %+v", r)
					}
					return e
				}
				b.acl = func(u appledouble.ACLUpdate) error {
					if !bytes.Equal(b.attrs()[appledouble.FinderInfoName], metadata.FinderInfo[:]) || !bytes.Equal(b.attrs()["ordinary"], []byte{1, 2}) || len(b.attrs()[appledouble.QuarantineName]) == 0 {
						t.Fatal("ACL ran before metadata")
					}
					var r aclmeta.ACLRestoreResult
					var e error
					if hfs {
						if !bytes.Equal(hroot.Children[0].ResourceFork, metadata.ResourceFork) {
							t.Fatal("ACL before fork")
						}
						r, e = hroot.RestoreACL(hroot.Children[0], u)
					} else {
						if !bytes.Equal(b.attrs()[appledouble.ResourceForkName], metadata.ResourceFork) {
							t.Fatal("ACL before fork")
						}
						r, e = root.RestoreACL(root.Children[0], u)
					}
					if e == nil && !r.Applied {
						return fmt.Errorf("ACL not applied: %+v", r)
					}
					return e
				}
				b.stat = func(hidden bool) error {
					if len(b.attrs()[hostdata.SecurityName]) == 0 || !hidden {
						t.Fatal("stat ran before ACL or invisible decision")
					}
					var r hostdata.ImageStatCopyResult
					var e error
					if hfs {
						r, e = hroot.CopyStat(hroot.Children[0], source, hostdata.StatCopyOptions{MakeInvisible: hidden})
					} else {
						r, e = root.CopyStat(root.Children[0], source, hostdata.StatCopyOptions{MakeInvisible: hidden})
					}
					if e == nil && !r.Applied {
						return fmt.Errorf("stat not applied: %+v", r)
					}
					return e
				}
				if variant == 0 {
					size, _ := b.ListXattrSize()
					names, _ := b.XattrNames(size)
					for _, n := range names {
						if e := b.RemoveXattr(n); e != nil {
							t.Fatal(e)
						}
					}
					if r := b.Quarantine(qbytes); r.Err != nil {
						t.Fatal(r.Err)
					}
					if e := b.WriteXattr("ordinary", []byte{1, 2}); e != nil {
						t.Fatal(e)
					}
					if e := b.WriteXattr(appledouble.FinderInfoName, metadata.FinderInfo[:]); e != nil {
						t.Fatal(e)
					}
					if _, e := b.CaptureForkState(); e != nil {
						t.Fatal(e)
					}
					if e := b.WriteXattr(appledouble.ResourceForkName, metadata.ResourceFork); e != nil {
						t.Fatal(e)
					}
					if r := b.ACL(text); r.Err != nil {
						t.Fatal(r.Err)
					}
					if r := b.Stat(true); r.Err != nil {
						t.Fatal(r.Err)
					}
				} else {
					delegate := pipelineBackend{run: func(stage hostdata.CopyStage) hostdata.CopyStageResult {
						if stage != hostdata.CopyStageUnpack {
							t.Fatal(stage)
						}
						r, e := hostdata.RestoreAppleDouble(data, hostdata.UnpackOptions{Stat: true}, b)
						if e != nil || !r.ReachedEnd || r.Code != 0 || len(r.Failures) != 0 || !r.MakeInvisible {
							t.Fatal(r, e)
						}
						return hostdata.CopyStageResult{Code: r.Code, Err: e}
					}}
					r, e := hostdata.RunCopyPipeline(hostdata.CopyPipelineOptions{SourceReady: true, DestinationReady: true, Unpack: true}, delegate)
					if e != nil || !r.Completed || len(r.Steps) != 1 {
						t.Fatal(r, e)
					}
				}
				expected := []string{"size", "names", "remove:skip#N", "remove:user.stale", "quarantine", "write:ordinary", "write:" + appledouble.FinderInfoName, "fork-stat", "write:" + appledouble.ResourceForkName, "acl", "stat"}
				if !reflect.DeepEqual(b.order, expected) {
					t.Fatal(b.order)
				}
				if _, ok := b.attrs()["skip#N"]; ok {
					t.Fatal("filtered source retained stale destination")
				}
				for _, path := range []int{0, 1} {
					if hfs {
						a := hroot.Children[path]
						if a.Mode != 0640 || *a.BSDFlags&0x8000 == 0 || !a.Times.Modify.Equal(source.Times.Modify) {
							t.Fatal(a)
						}
					} else {
						a := root.Children[path]
						if a.Mode != 0640 || *a.BSDFlags&0x8000 == 0 || !a.Times.Modify.Equal(source.Times.Modify) {
							t.Fatal(a)
						}
					}
				}
				file, e := os.Create(filepath.Join(t.TempDir(), "unpack.img"))
				if e != nil {
					t.Fatal(e)
				}
				defer file.Close()
				var volume imagesecurity.Volume
				if hfs {
					e = hfsplus.CreateImage(file, 64<<20, "UNPACK", hroot, &hfsplus.CreateOptions{CaseInsensitive: kind == "hfsplus"})
					if e == nil {
						volume, e = hfsplus.New(file)
					}
				} else {
					e = apfswrite.CreateContainer(file, 64<<20, &apfswrite.CreateOptions{Root: root, VolumeName: "UNPACK", CaseSensitive: kind == "apfs-sensitive", Snapshots: []apfswrite.SnapshotSpec{{Name: "unpack"}}})
					if e == nil {
						var c *apfs.Container
						c, e = apfs.Open(file, nil)
						if e == nil {
							var vs []*apfs.Volume
							vs, e = c.Volumes()
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
				for _, name := range []string{"a", "b"} {
					attrs, e := volume.Xattrs(name)
					if e != nil {
						t.Fatal(e)
					}
					if !bytes.Equal(attrs[appledouble.ResourceForkName], metadata.ResourceFork) || !bytes.Equal(attrs["ordinary"], []byte{1, 2}) || len(attrs[hostdata.SecurityName]) == 0 || len(attrs[appledouble.QuarantineName]) == 0 {
						t.Fatal(name, attrs)
					}
					for _, n := range []string{"user.stale", "skip#N"} {
						if _, ok := attrs[n]; ok {
							t.Fatal("stale", n)
						}
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
				t.Fatal("composition changed image", hashes)
			}
			t.Logf("unpack restoration image %s SHA256 %s", kind, hashes[0])
		})
	}
}
