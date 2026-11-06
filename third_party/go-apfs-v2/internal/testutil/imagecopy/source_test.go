package imagecopy_test

import (
	"crypto/sha256"
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

func sourceImage(t *testing.T, kind string, root *apfswrite.Entry, hroot *hfsplus.Entry) (imagesecurity.Volume, *os.File, string) {
	t.Helper()
	file, err := os.Create(filepath.Join(t.TempDir(), "source.img"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	var volume imagesecurity.Volume
	if strings.HasPrefix(kind, "apfs") {
		if err = apfswrite.CreateContainer(file, 64<<20, &apfswrite.CreateOptions{Root: root, VolumeName: "SOURCE", CaseSensitive: kind == "apfs-sensitive"}); err != nil {
			t.Fatal(err)
		}
		c, e := apfs.Open(file, nil)
		if e != nil {
			t.Fatal(e)
		}
		v, e := c.Volumes()
		if e != nil || len(v) != 1 {
			t.Fatal(e)
		}
		volume = v[0]
	} else {
		if hroot == nil {
			hroot = imagesecurity.HFSTree(root)
		}
		if err = hfsplus.CreateImage(file, 64<<20, "SOURCE", hroot, &hfsplus.CreateOptions{CaseInsensitive: kind == "hfsplus"}); err != nil {
			t.Fatal(err)
		}
		volume, err = hfsplus.New(file)
		if err != nil {
			t.Fatal(err)
		}
	}
	return volume, file, sourceImageHash(t, file)
}
func sourceImageHash(t *testing.T, file *os.File) string {
	t.Helper()
	hash := sha256.New()
	if _, e := file.Seek(0, 0); e != nil {
		t.Fatal(e)
	}
	if _, e := io.Copy(hash, file); e != nil {
		t.Fatal(e)
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}
func TestImageSecuritySourceIntegration(t *testing.T) {
	kinds := []string{"apfs", "apfs-sensitive", "hfsx", "hfsplus"}
	for _, from := range kinds {
		t.Run(from, func(t *testing.T) {
			sourceTree, cases := imagesecurity.Tree(501, 20)
			volume, sourceFile, sourceHash := sourceImage(t, from, sourceTree, nil)
			for _, to := range kinds {
				t.Run(to, func(t *testing.T) {
					var hashes [2]string
					var results []hostdata.SecurityCopyResult
					for pass := 0; pass < 2; pass++ {
						root, targetCases := imagesecurity.Tree(88, 89)
						hroot := imagesecurity.HFSTree(root)
						if len(targetCases) != len(cases) {
							t.Fatal("shape")
						}
						for i, c := range cases {
							target := root
							htarget := hroot
							if i > 0 {
								target = root.Children[i-1]
								htarget = hroot.Children[i-1]
							}
							flags := 1 + i%3
							options := hostdata.SecurityCopyOptions{ACL: flags&1 != 0, Stat: flags&2 != 0}
							// A hard-link alias must receive the same selected stage as its peer.
							if target.LinkGroup != 0 {
								flags = 1 + int(target.LinkGroup%3)
								options.ACL, options.Stat = flags&1 != 0, flags&2 != 0
							}
							var copied hostdata.SecurityCopyResult
							var err error
							if pass == 0 {
								capture := hostdata.ImageSecurityCapture(volume, c.Name)
								var r hostdata.SecuritySourceCopyResult
								if strings.HasPrefix(to, "apfs") {
									r, err = root.CopySecurityFrom(target, capture, options)
								} else {
									r, err = hroot.CopySecurityFrom(htarget, capture, options)
								}
								if !r.Capture.Completed || r.Capture.Fallback || len(r.Capture.Failures) != 0 {
									t.Fatal(c.Name, r, err)
								}
								independently, e := volume.Security(c.Name)
								if e != nil || !reflect.DeepEqual(r.Capture.Source, independently.Source) {
									t.Fatal("acquired source", c.Name, e)
								}
								copied = r.Copy
								results = append(results, copied)
							} else {
								snapshot, e := volume.Security(c.Name)
								if e != nil {
									t.Fatal(e)
								}
								if strings.HasPrefix(to, "apfs") {
									copied, err = root.CopySecurity(target, snapshot.Source, options)
								} else {
									copied, err = hroot.CopySecurity(htarget, snapshot.Source, options)
								}
								if !reflect.DeepEqual(copied, results[i]) {
									t.Fatal("copy result differs", c.Name)
								}
							}
							if err != nil || !copied.Completed || len(copied.Failures) != 0 {
								t.Fatal(c.Name, copied, err)
							}
						}
						written, _, hash := sourceImage(t, to, root, hroot)
						hashes[pass] = hash
						for _, c := range cases {
							got, e := written.Security(c.Name)
							if e != nil {
								t.Fatal(c.Name, e)
							}
							if got.Source.Mode&0170000 != uint32(c.Mode)&0170000 {
								t.Fatal("file type changed", c.Name)
							}
							if c.Kind == "file" || strings.HasPrefix(c.Kind, "hard-") {
								f, e := written.Open(c.Name)
								if e != nil {
									t.Fatal(e)
								}
								data, e := io.ReadAll(f)
								f.Close()
								if e != nil || string(data) != "payload" {
									t.Fatal("payload", c.Name, e)
								}
							}
						}
					}
					if hashes[0] != hashes[1] {
						t.Fatal("acquired/precaptured bytes differ", hashes)
					}
					t.Logf("source %s to %s: %d acquisitions; SHA256 %s", from, to, len(cases), hashes[0])
				})
			}
			if sourceImageHash(t, sourceFile) != sourceHash {
				t.Fatal("source image changed")
			}
		})
	}
}

func TestImageSecuritySourceFailures(t *testing.T) {
	failure := errors.New("source read failed")
	for _, hfs := range []bool{false, true} {
		t.Run(fmt.Sprint(hfs), func(t *testing.T) {
			target := &apfswrite.Entry{Name: "file", Mode: 0644, UID: 42, Data: []byte("payload")}
			root := &apfswrite.Entry{Children: []*apfswrite.Entry{target}}
			hroot := imagesecurity.HFSTree(root)
			calls := 0
			capture := hostdata.SecuritySourceCapture{ReadSecurity: func() (hostdata.SecurityCopySource, error) { calls++; return hostdata.SecurityCopySource{}, failure }}
			copyFrom := func(valid bool, options hostdata.SecurityCopyOptions) (hostdata.SecuritySourceCopyResult, error) {
				if hfs {
					var r *hfsplus.Entry
					if valid {
						r = hroot
					}
					return r.CopySecurityFrom(hroot.Children[0], capture, options)
				}
				var r *apfswrite.Entry
				if valid {
					r = root
				}
				return r.CopySecurityFrom(target, capture, options)
			}
			r, e := copyFrom(false, hostdata.SecurityCopyOptions{})
			if e != nil || !r.Copy.Completed || calls != 0 {
				t.Fatal(r, e, calls)
			}
			r, e = copyFrom(false, hostdata.SecurityCopyOptions{ACL: true})
			if !errors.Is(e, fs.ErrInvalid) || calls != 0 {
				t.Fatal(r, e, calls)
			}
			r, e = copyFrom(true, hostdata.SecurityCopyOptions{ACL: true})
			if !errors.Is(e, failure) || calls != 1 || r.Copy.Writes != 0 || target.UID != 42 || target.Mode != 0644 || hroot.Children[0].UID != 42 || hroot.Children[0].Mode != 0644 {
				t.Fatal(r, e, calls)
			}
		})
	}
}
