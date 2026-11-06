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
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagesecurity"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func TestImageTimesNativeReplay(t *testing.T) {
	data, e := os.ReadFile("../../../testdata/appledouble/native/image-times.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	z, e := gzip.NewReader(bytes.NewReader(data))
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var fixture imagesecurity.Fixture
	if e = json.NewDecoder(z).Decode(&fixture); e != nil {
		t.Fatal(e)
	}
	if len(fixture.Cases) != 296 || len(fixture.Images) != 8 {
		t.Fatal("incomplete native corpus")
	}
	helper, e := os.ReadFile("../../../testdata/appledouble/native/image-security.c")
	if e != nil {
		t.Fatal(e)
	}
	helper = bytes.ReplaceAll(helper, []byte("\r\n"), []byte("\n"))
	if fmt.Sprintf("%x", sha256.Sum256(helper)) != fixture.HelperSHA256 {
		t.Fatal("helper hash")
	}
	native := map[string]imagesecurity.NativeCase{}
	for _, c := range fixture.Cases {
		native[c.Filesystem+"/"+c.Case.Name] = c
	}
	for _, kind := range []string{"apfs", "apfs-sensitive", "hfsx", "hfsplus"} {
		for _, clamp := range []bool{false, true} {
			name := kind + "-times"
			if clamp {
				name += "-clamp"
			}
			t.Run(name, func(t *testing.T) {
				root, cases := imagesecurity.TimeTree(clamp)
				before, _ := json.Marshal(root)
				file, e := os.Create(filepath.Join(t.TempDir(), "times.img"))
				if e != nil {
					t.Fatal(e)
				}
				defer file.Close()
				var v imagesecurity.Volume
				if strings.HasPrefix(kind, "apfs") {
					e = apfswrite.CreateContainer(file, 64<<20, &apfswrite.CreateOptions{Root: root, VolumeName: "SECURITY", CaseSensitive: kind == "apfs-sensitive", ClampModTimes: clamp, Snapshots: []apfswrite.SnapshotSpec{{Name: "times"}}})
					if e != nil {
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
					n, e := vs[0].NumberOfSnapshots()
					if e != nil || n != 1 {
						t.Fatal("snapshot", n, e)
					}
				} else {
					e = hfsplus.CreateImage(file, 64<<20, "SECURITY", imagesecurity.HFSTree(root), &hfsplus.CreateOptions{CaseInsensitive: kind == "hfsplus", ClampModTimes: clamp})
					if e != nil {
						t.Fatal(e)
					}
					v, e = hfsplus.New(file)
					if e != nil {
						t.Fatal(e)
					}
				}
				for _, tc := range cases {
					t.Run(tc.Name, func(t *testing.T) {
						got, e := v.FileTimes(tc.Name)
						if e != nil {
							t.Fatal(e)
						}
						actual := [4]int64{got.Birth.UnixNano(), got.Modify.UnixNano(), got.Change.UnixNano(), got.Access.UnixNano()}
						want := *tc.Times
						if !strings.HasPrefix(kind, "apfs") {
							for i, x := range want {
								want[i] = time.Unix(0, x).Unix() * 1e9
							}
						}
						n, ok := native[name+"/"+tc.Name]
						if !ok || n.Native.Code != 0 || n.Native.ReferenceCode != 0 || !n.Native.SameIdentity || n.Native.Times != want || actual != want {
							t.Fatalf("times %v want%v native%v", actual, want, n.Native.Times)
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
					if _, e := v.FileTimes(bad); e == nil {
						t.Fatal("accepted", bad)
					}
				}
				after, _ := json.Marshal(root)
				if !bytes.Equal(before, after) {
					t.Fatal("caller mutated")
				}
				h := sha256.New()
				if _, e = file.Seek(0, 0); e != nil {
					t.Fatal(e)
				}
				if _, e = io.Copy(h, file); e != nil {
					t.Fatal(e)
				}
				sum := fmt.Sprintf("%x", h.Sum(nil))
				if sum != fixture.Images[name] {
					t.Fatalf("image hash %s != %s", sum, fixture.Images[name])
				}
				t.Logf("timestamp image %s SHA256 %s", name, sum)
			})
		}
	}
}

var errRefuseImageWrite = errors.New("unexpected write")

type refuseWrite struct{ calls int }

func (w *refuseWrite) WriteAt([]byte, int64) (int, error) {
	w.calls++
	return 0, errRefuseImageWrite
}
func TestImageTimesInvalidBeforeWrite(t *testing.T) {
	for _, rootTime := range []bool{false, true} {
		for _, hfs := range []bool{false, true} {
			invalid := hostdata.FileTimes{Birth: time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)}
			root := &apfswrite.Entry{Children: []*apfswrite.Entry{{Name: "file", Data: []byte("payload")}}}
			if rootTime {
				root.Times = &invalid
			} else {
				root.Children[0].Times = &invalid
			}
			w := &refuseWrite{}
			var err error
			if hfs {
				err = hfsplus.CreateImage(w, 64<<20, "INVALID", imagesecurity.HFSTree(root), nil)
			} else {
				err = apfswrite.CreateContainer(w, 64<<20, &apfswrite.CreateOptions{Root: root})
			}
			if !errors.Is(err, fs.ErrInvalid) || w.calls != 0 {
				t.Fatalf("invalid %v writes%d", err, w.calls)
			}
		}
	}
	var a *apfs.Volume
	var h *hfsplus.Volume
	for _, v := range []interface {
		FileTimes(string) (hostdata.FileTimes, error)
	}{a, h} {
		if _, e := v.FileTimes("."); !errors.Is(e, fs.ErrInvalid) {
			t.Fatal(e)
		}
	}
}

func TestImageTimesSecurityStages(t *testing.T) {
	root, _ := imagesecurity.TimeTree(false)
	hroot := imagesecurity.HFSTree(root)
	before, _ := json.Marshal(root.Times)
	source := hostdata.SecurityCopySource{UID: 501, GID: 20, Mode: 040700}
	if _, e := root.CopySecurity(root, source, hostdata.SecurityCopyOptions{Stat: true}); e != nil {
		t.Fatal(e)
	}
	if _, e := hroot.CopySecurity(hroot, source, hostdata.SecurityCopyOptions{Stat: true}); e != nil {
		t.Fatal(e)
	}
	for _, times := range []*hostdata.FileTimes{root.Times, hroot.Times} {
		after, _ := json.Marshal(times)
		if !bytes.Equal(before, after) {
			t.Fatal("security copy changed timestamps")
		}
	}
}
