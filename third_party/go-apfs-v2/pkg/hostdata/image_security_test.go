package hostdata_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func TestImageSecurityProfiles(t *testing.T) {
	for _, tc := range imagesecurity.Profiles() {
		t.Run(tc.Name, func(t *testing.T) {
			before := bytes.Clone(tc.Data)
			got := hostdata.DecodeImageSecurity(42, 43, 0106755, tc.Data)
			if got.Disposition != tc.Disposition || *got.Source.Properties.UID != 42 || *got.Source.Properties.GID != 43 || *got.Source.Properties.Mode != 0106755 {
				t.Fatalf("unexpected snapshot %+v", got)
			}
			if !bytes.Equal(tc.Data, before) {
				t.Fatal("input mutated")
			}
			if got.Disposition == hostdata.SecurityRecordACL {
				raw := got.Source.Properties.RawSecurity
				if raw == nil || len(raw.Trailing) != 0 || *got.Source.Properties.OwnerUUID != [16]byte{0x11} {
					t.Fatal("ACL properties")
				}
				raw.ACL.Entries[0].Rights = 123
				got.Source.Properties.OwnerUUID[0] = 44
				if !bytes.Equal(tc.Data, before) {
					t.Fatal("snapshot aliases image")
				}
			} else if got.Source.Properties.RawSecurity != nil || got.Source.Properties.OwnerUUID != nil || got.Source.Properties.GroupUUID != nil {
				t.Fatal("ignored storage exposed properties")
			}
		})
	}
	for _, size := range []uint64{0, 43, 45, 67, 3117, 3140, ^uint64(0)} {
		if hostdata.SecurityRecordSizeValid(size) {
			t.Fatalf("accepted size %d", size)
		}
	}
}

func TestImageSecurityNativeImages(t *testing.T) {
	b, e := os.ReadFile("../../testdata/appledouble/native/image-security.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	z, e := gzip.NewReader(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var f imagesecurity.Fixture
	if e = json.NewDecoder(z).Decode(&f); e != nil {
		t.Fatal(e)
	}
	for name, want := range map[string]string{"image-security.c": f.HelperSHA256, "security-copy.c": f.ParentSHA256} {
		helper, e := os.ReadFile("../../testdata/appledouble/native/" + name)
		if e != nil {
			t.Fatal(e)
		}
		helper = bytes.ReplaceAll(helper, []byte("\r\n"), []byte("\n"))
		if fmt.Sprintf("%x", sha256.Sum256(helper)) != want {
			t.Fatal("helper provenance: " + name)
		}
	}
	if f.StatxSHA256 != "5a05eabc7d870f2c1a98c4e3b828d020e4a51e4b60c6887d955422add747730d" || f.XNUSHA256 != "26cd0285298c7eafe9ff86387d9fe273f5cbdf965f850458357eba4328303e53" || f.CopyfileSHA256 != "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c" || f.ChmodSHA256 != "31c8a6c3729759582796700827583b17639ed0324f44dafb4927f1332bc040ff" {
		t.Fatal("Apple source provenance")
	}
	if len(f.Cases) != 1444 || len(f.Images) != 4 {
		t.Fatalf("incomplete corpus: %d cases", len(f.Cases))
	}
	wantHFS := map[string]string{
		"UnicodeWrappers.c":     "7300de813b94d41d14faf9aa2a0ddf436010bb43d258f81fc92ab841bc7157f2",
		"UCStringCompareData.h": "88773669ce79ebe2d6bcc84d3341c3c2586e649984ac97453adb1b8706440464",
		"hfs_link.c":            "1238abcd80ada12e254a8d0e45dd82d990693f3dea047ecd7c7345c7a1410078",
	}
	if !reflect.DeepEqual(f.HFSSources, wantHFS) {
		t.Fatal("HFS source provenance")
	}
	tree, cases := imagesecurity.Tree(f.ActorUID, f.ActorGID)
	for _, kind := range []string{"apfs", "apfs-sensitive", "hfsx", "hfsplus"} {
		t.Run(kind, func(t *testing.T) {
			file, e := os.Create(filepath.Join(t.TempDir(), "security.img"))
			if e != nil {
				t.Fatal(e)
			}
			defer file.Close()
			var volume imagesecurity.Volume
			if strings.HasPrefix(kind, "apfs") {
				if e = apfswrite.CreateContainer(file, 64<<20, &apfswrite.CreateOptions{Root: tree, VolumeName: "SECURITY", CaseSensitive: kind == "apfs-sensitive"}); e != nil {
					t.Fatal(e)
				}
				c, e := apfs.Open(file, nil)
				if e != nil {
					t.Fatal(e)
				}
				vs, e := c.Volumes()
				if e != nil {
					t.Fatal(e)
				}
				volume = vs[0]
			} else {
				if e = hfsplus.CreateImage(file, 64<<20, "SECURITY", imagesecurity.HFSTree(tree), &hfsplus.CreateOptions{CaseInsensitive: kind == "hfsplus"}); e != nil {
					t.Fatal(e)
				}
				volume, e = hfsplus.New(file)
				if e != nil {
					t.Fatal(e)
				}
			}
			seen := map[string]bool{}
			for _, n := range f.Cases {
				if n.Filesystem != kind {
					continue
				}
				seen[n.Case.Name] = true
				t.Run(n.Case.Name, func(t *testing.T) {
					native := n.Native
					if native.Code != 0 || native.ReferenceCode != 0 || native.Errno != 0 || native.ReferenceErrno != 0 || !native.SameIdentity || !reflect.DeepEqual(native.Properties, native.ReferenceProperties) {
						t.Fatal("failed native oracle")
					}
					got, e := volume.Security(n.Case.Name)
					if e != nil {
						t.Fatal(e)
					}
					if got.Disposition != n.Case.Disposition || got.Source.UID != native.UID || got.Source.GID != native.GID || got.Source.Mode != native.Mode || !reflect.DeepEqual(securitycopy.PropertiesFromGo(got.Source.Properties), native.Properties) {
						t.Fatalf("native mismatch: %+v", got)
					}
					if got.Source.UID != n.Case.UID || got.Source.GID != n.Case.GID || got.Source.Mode != uint32(n.Case.Mode) {
						t.Fatal("fixture ownership/mode not retained")
					}
					again, e := volume.Security(n.Case.Name)
					if e != nil {
						t.Fatal(e)
					}
					*got.Source.Properties.UID = 999
					if got.Source.Properties.RawSecurity != nil {
						got.Source.Properties.RawSecurity.ACL.Entries[0].Rights = 999
					}
					last, e := volume.Security(n.Case.Name)
					if e != nil || !reflect.DeepEqual(last, again) {
						t.Fatal("caller mutation escaped snapshot")
					}
					if n.Case.Kind == "file" || strings.HasPrefix(n.Case.Kind, "hard-") {
						data, e := fs.ReadFile(volume, n.Case.Name)
						if e != nil || string(data) != "payload" {
							t.Fatal("inode payload mismatch", e)
						}
					}
				})
			}
			if len(seen) != len(cases) {
				t.Fatalf("corpus coverage: %d/%d", len(seen), len(cases))
			}
			for _, tc := range cases {
				if !seen[tc.Name] {
					t.Fatal("missing case " + tc.Name)
				}
			}
			for _, name := range []string{"", "/file", "../file", "missing", "missing/child", "absent-actor-file/child"} {
				got, e := volume.Security(name)
				var pe *fs.PathError
				if e == nil || !errors.As(e, &pe) || pe.Op != "security" || pe.Path != name || !reflect.DeepEqual(got, hostdata.ImageSecurity{}) {
					t.Fatalf("path failure %q: %+v %v", name, got, e)
				}
			}
		})
	}
}

func FuzzImageSecurity(f *testing.F) {
	for _, p := range imagesecurity.Profiles() {
		f.Add(p.Data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		before := bytes.Clone(data)
		a := hostdata.DecodeImageSecurity(42, 43, 0106755, data)
		b := hostdata.DecodeImageSecurity(42, 43, 0106755, data)
		if !reflect.DeepEqual(a, b) || !bytes.Equal(data, before) {
			t.Fatal("non-deterministic or mutated input")
		}
		if a.Disposition == hostdata.SecurityRecordACL {
			if !hostdata.SecurityRecordSizeValid(uint64(len(data))) || a.Source.Properties.RawSecurity == nil {
				t.Fatal("invalid accepted extent")
			}
			raw := a.Source.Properties.RawSecurity
			if raw.ACL == nil || len(raw.ACL.Entries) == 0 || len(raw.ACL.Entries) > 128 || len(raw.Trailing) != 0 {
				t.Fatal("invalid accepted ACL")
			}
			if _, e := a.Source.Properties.ChmodArguments(); e != nil {
				t.Fatal(e)
			}
		}
	})
}
