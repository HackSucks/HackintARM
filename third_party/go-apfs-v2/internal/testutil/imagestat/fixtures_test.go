package imagestat_test

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
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagesecurity"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagestat"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/statcopy"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func fixture(t *testing.T) imagesecurity.Fixture {
	t.Helper()
	data, e := os.ReadFile("../../../testdata/appledouble/native/image-stat.json.gz")
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
	if len(f.Cases) != 580 || len(f.Images) != 4 || len(f.StatModels) != 32 || len(f.NativeXattrs) != 580 {
		t.Fatal("incomplete stat corpus")
	}
	if f.StatSources["copyfile_private.h"] != "8ac427e2c1dbe0ca92cfe2fbf114df90fd747f3fbe25c2a4919ff941a1be81c5" || f.StatSources["fsctl.h"] != "dae81f19610f25fb7905b5c725f728fec4b8b4978f6214374415d420ffac258d" || f.CopyfileSHA256 != "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c" {
		t.Fatal("source provenance")
	}
	helpers := map[string]string{"testdata/appledouble/native/image-security.c": f.HelperSHA256, "testdata/appledouble/native/security-copy.c": f.ParentSHA256}
	if len(f.Helpers) != 2 {
		t.Fatal("helper provenance")
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
	for i, tc := range f.StatModels {
		expected := imagestat.Models()[i]
		if tc.Name != expected.Name || tc.SourceFlags != expected.SourceFlags || tc.TargetFlags != expected.TargetFlags || tc.Options != expected.Options {
			t.Fatal("model parameters")
		}
		if _, _, e := statcopy.Replay(tc); e != nil {
			t.Fatal(e)
		}
	}
	return f
}
func TestImageStatNativeReplay(t *testing.T) {
	f := fixture(t)
	native := map[string]imagesecurity.NativeCase{}
	for _, c := range f.Cases {
		key := c.Filesystem + "/" + c.Case.Name
		if _, ok := native[key]; ok {
			t.Fatal("duplicate")
		}
		native[key] = c
	}
	for _, kind := range []string{"apfs", "apfs-sensitive", "hfsx", "hfsplus"} {
		t.Run(kind, func(t *testing.T) {
			hfs := strings.HasPrefix(kind, "hfs")
			before, _ := json.Marshal(f.StatModels)
			root, hroot, cases, e := imagestat.Build(f.StatModels, hfs)
			if e != nil {
				t.Fatal(e)
			}
			after, _ := json.Marshal(f.StatModels)
			if !bytes.Equal(before, after) {
				t.Fatal("source mutation")
			}
			file, e := os.Create(filepath.Join(t.TempDir(), "stat.img"))
			if e != nil {
				t.Fatal(e)
			}
			defer file.Close()
			var v imagesecurity.Volume
			if hfs {
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
				vs, e := c.Volumes()
				if e != nil || len(vs) != 1 {
					t.Fatal(e)
				}
				v = vs[0]
			}
			for _, tc := range cases {
				t.Run(tc.Name, func(t *testing.T) {
					n, ok := native[kind+"-stat/"+tc.Name]
					if !ok || !reflect.DeepEqual(n.Case, tc) {
						t.Fatal("case")
					}
					if n.Native.Code != 0 || n.Native.ReferenceCode != 0 || !n.Native.SameIdentity || !reflect.DeepEqual(n.Native.Properties, n.Native.ReferenceProperties) {
						t.Fatal("native capture")
					}
					flags, e := v.BSDFlags(tc.Name)
					if e != nil || flags != *tc.Flags || flags != n.Native.Flags {
						t.Fatal("flags", e)
					}
					times, e := v.FileTimes(tc.Name)
					if e != nil {
						t.Fatal(e)
					}
					got := [4]int64{times.Birth.UnixNano(), times.Modify.UnixNano(), times.Change.UnixNano(), times.Access.UnixNano()}
					want := *tc.Times
					if hfs {
						for i, x := range want {
							want[i] = time.Unix(0, x).Unix() * 1e9
						}
					}
					if got != want || n.Native.Times != want {
						t.Fatal("times", got, want)
					}
					security, e := v.Security(tc.Name)
					if e != nil || security.Source.UID != tc.UID || security.Source.GID != tc.GID || security.Source.Mode != uint32(tc.Mode) || n.Native.UID != tc.UID || n.Native.GID != tc.GID || n.Native.Mode != uint32(tc.Mode) {
						t.Fatal("numeric metadata", e)
					}
					attrs, e := v.Xattrs(tc.Name)
					if e != nil || string(attrs["org.example.keep"]) != "kept" {
						t.Fatal("xattr", e)
					}
					x := f.NativeXattrs[kind+"-stat/"+tc.Name]["org.example.keep"]
					if x.Errno != 0 || x.Length != 4 || x.Value == nil || *x.Value != "6b657074" {
						t.Fatal("native xattr")
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
							t.Fatal("symlink", e)
						}
					}
				})
			}
			hash := sha256.New()
			if _, e = file.Seek(0, 0); e != nil {
				t.Fatal(e)
			}
			if _, e = io.Copy(hash, file); e != nil {
				t.Fatal(e)
			}
			sum := fmt.Sprintf("%x", hash.Sum(nil))
			if sum != f.Images[kind+"-stat"] {
				t.Fatal("image hash", sum)
			}
			t.Logf("stat image %s-stat SHA256 %s", kind, sum)
		})
	}
}

// This checks that the independent APIs preserve unselected metadata. It does
// not prescribe unpack ordering: native unpack applies its ACL before stat.
func TestImageStatAPIBindingAndMetadataIndependence(t *testing.T) {
	for _, hfs := range []bool{false, true} {
		t.Run(fmt.Sprint(hfs), func(t *testing.T) {
			times := imagestat.InitialTimes()
			flags := uint32(0)
			security := &appledouble.FileSecurity{OwnerUUID: [16]byte{1}, ACL: &appledouble.ACL{Entries: []appledouble.ACLEntry{{Flags: 1, Rights: 1}}}}
			raw, e := security.MarshalBinary()
			if e != nil {
				t.Fatal(e)
			}
			root := &apfswrite.Entry{Times: &times, BSDFlags: &flags, Xattrs: map[string][]byte{hostdata.SecurityName: raw, "keep": {1}}}
			hroot := imagesecurity.HFSTree(root)
			source := hostdata.StatCopySource{UID: 17, GID: 18, Mode: 0100000, Times: hostdata.FileTimes{Modify: time.Unix(0, 0), Access: time.Unix(0, 0)}}
			var r hostdata.ImageStatCopyResult
			if hfs {
				r, e = hroot.CopyStat(hroot, source, hostdata.StatCopyOptions{})
			} else {
				r, e = root.CopyStat(root, source, hostdata.StatCopyOptions{})
			}
			if e != nil || !r.Applied {
				t.Fatal(r, e)
			}
			var attrs map[string][]byte
			var mode os.FileMode
			var explicit bool
			if hfs {
				attrs, mode, explicit = hroot.Xattrs, hroot.Mode, hroot.ModeExplicit
			} else {
				attrs, mode, explicit = root.Xattrs, root.Mode, root.ModeExplicit
			}
			if mode != os.ModeDir || !explicit || !bytes.Equal(attrs[hostdata.SecurityName], raw) || !bytes.Equal(attrs["keep"], []byte{1}) {
				t.Fatal("unselected metadata or explicit root mode")
			}
			replacement := appledouble.ACLUpdate{ACL: &appledouble.ACL{Entries: []appledouble.ACLEntry{{Flags: 1, Rights: 2}}}}
			if hfs {
				_, e = hroot.RestoreACL(hroot, replacement)
			} else {
				_, e = root.RestoreACL(root, replacement)
			}
			if e != nil {
				t.Fatal(e)
			}
			if hfs {
				attrs = hroot.Xattrs
				if hroot.UID != 17 || !hroot.Times.Modify.Equal(source.Times.Modify) {
					t.Fatal("deferred replacement changed stat")
				}
			} else {
				attrs = root.Xattrs
				if root.UID != 17 || !root.Times.Modify.Equal(source.Times.Modify) {
					t.Fatal("deferred replacement changed stat")
				}
			}
			stored, e := appledouble.ParseFileSecurity(attrs[hostdata.SecurityName])
			if e != nil || stored.ACL.Entries[0].Rights != 2 || stored.OwnerUUID != security.OwnerUUID {
				t.Fatal("deferred ACL", e)
			}
		})
	}
	for _, hfs := range []bool{false, true} {
		var err error
		if hfs {
			var root *hfsplus.Entry
			_, err = root.CopyStat(nil, hostdata.StatCopySource{}, hostdata.StatCopyOptions{})
		} else {
			var root *apfswrite.Entry
			_, err = root.CopyStat(nil, hostdata.StatCopySource{}, hostdata.StatCopyOptions{})
		}
		if !errors.Is(err, fs.ErrInvalid) {
			t.Fatal(err)
		}
	}
}
