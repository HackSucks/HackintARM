package imagecopy_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagesecurity"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

type imageVolumePolicy func(hostdata.SecurityCopyVolume) (bool, error)

func (f imageVolumePolicy) NoSetID(v hostdata.SecurityCopyVolume) (bool, error) { return f(v) }

func TestImageSecurityCopyVolumePolicy(t *testing.T) {
	failure := errors.New("uncaptured mount state")
	for _, kind := range []string{"apfs", "apfs-sensitive", "hfsx", "hfsplus"} {
		t.Run(kind, func(t *testing.T) {
			var hashes [2]string
			for pass := 0; pass < 2; pass++ {
				var entries []*apfswrite.Entry
				var expected []uint32
				var options []hostdata.SecurityCopyOptions
				for flags := 1; flags <= 3; flags++ {
					for override := 0; override < 3; override++ {
						for s := 0; s < 3; s++ {
							for d := 0; d < 3; d++ {
								i := len(options)
								mode := uint32(06755)
								if flags == 1 {
									mode = 06711
								} else if override != 2 && (override == 1 || s == 1 || d == 1) {
									mode &^= 06000
								}
								expected = append(expected, 0100000|mode)
								option := hostdata.SecurityCopyOptions{ACL: flags&1 != 0, Stat: flags&2 != 0, ForbidCopySetID: override == 1, AlwaysCopySetID: override == 2}
								if pass == 0 {
									option.VolumePolicy = imageVolumePolicy(func(v hostdata.SecurityCopyVolume) (bool, error) {
										state := s
										if v == hostdata.SecurityCopyDestinationVolume {
											state = d
										}
										if state == 2 {
											return false, failure
										}
										return state == 1, nil
									})
								} else {
									option.SourceNoSetID, option.DestinationNoSetID = s == 1, d == 1
								}
								options = append(options, option)
								for _, suffix := range []string{"a", "b"} {
									entries = append(entries, &apfswrite.Entry{Name: fmt.Sprintf("case-%03d-%s", i, suffix), Mode: os.ModeSetuid | os.ModeSetgid | 0711, ModeExplicit: true, UID: 42, GID: 43, LinkGroup: uint64(i + 1), Data: []byte("payload"), Xattrs: map[string][]byte{"user.keep": []byte("kept")}})
								}
							}
						}
					}
				}
				root := &apfswrite.Entry{Children: entries}
				hroot := imagesecurity.HFSTree(root)
				source := hostdata.DecodeImageSecurity(42, 43, 0106755, nil).Source
				source.Properties.RawSecurity = &appledouble.FileSecurity{ACL: &appledouble.ACL{Entries: []appledouble.ACLEntry{{Principal: [16]byte{1}, Flags: 1, Rights: 1}}}}
				for i, option := range options {
					var result hostdata.SecurityCopyResult
					var err error
					if strings.HasPrefix(kind, "apfs") {
						result, err = root.CopySecurity(entries[2*i], source, option)
					} else {
						result, err = hroot.CopySecurity(hroot.Children[2*i], source, option)
					}
					if err != nil || !result.Completed || len(result.Failures) != 0 {
						t.Fatal(i, result, err)
					}
					if pass == 1 && len(result.VolumeQueries) != 0 {
						t.Fatal("precaptured policy queried")
					}
					if pass == 0 && option.Stat && !option.AlwaysCopySetID && !option.ForbidCopySetID && len(result.VolumeQueries) == 0 {
						t.Fatal("missing volume queries")
					}
				}
				file, err := os.Create(filepath.Join(t.TempDir(), "copy.img"))
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				var volume imagesecurity.Volume
				if strings.HasPrefix(kind, "apfs") {
					if err = apfswrite.CreateContainer(file, 64<<20, &apfswrite.CreateOptions{Root: root, VolumeName: "VOLUME", CaseSensitive: kind == "apfs-sensitive"}); err != nil {
						t.Fatal(err)
					}
					container, e := apfs.Open(file, nil)
					if e != nil {
						t.Fatal(e)
					}
					volumes, e := container.Volumes()
					if e != nil || len(volumes) != 1 {
						t.Fatal(e)
					}
					volume = volumes[0]
				} else {
					if err = hfsplus.CreateImage(file, 64<<20, "VOLUME", hroot, &hfsplus.CreateOptions{CaseInsensitive: kind == "hfsplus"}); err != nil {
						t.Fatal(err)
					}
					volume, err = hfsplus.New(file)
					if err != nil {
						t.Fatal(err)
					}
				}
				for i, want := range expected {
					var snapshots [2]hostdata.ImageSecurity
					for j, suffix := range []string{"a", "b"} {
						name := fmt.Sprintf("case-%03d-%s", i, suffix)
						captured, e := volume.Security(name)
						if e != nil || captured.Source.Mode != want || captured.Source.UID != 42 || captured.Source.GID != 43 {
							t.Fatal(name, captured, e, "want", want)
						}
						if (captured.Source.Properties.RawSecurity != nil) != options[i].ACL {
							t.Fatal("ACL selection", name)
						}
						snapshots[j] = captured
						f, e := volume.Open(name)
						if e != nil {
							t.Fatal(e)
						}
						data, e := io.ReadAll(f)
						f.Close()
						if e != nil || string(data) != "payload" {
							t.Fatal(name, e)
						}
					}
					if !reflect.DeepEqual(snapshots[0], snapshots[1]) {
						t.Fatal("hard-link security diverged", i)
					}
				}
				if _, err = file.Seek(0, 0); err != nil {
					t.Fatal(err)
				}
				hash := sha256.New()
				if _, err = io.Copy(hash, file); err != nil {
					t.Fatal(err)
				}
				hashes[pass] = fmt.Sprintf("%x", hash.Sum(nil))
			}
			if hashes[0] != hashes[1] {
				t.Fatal("queried and precaptured image bytes differ", hashes)
			}
			t.Log("queried/precaptured SHA256", hashes[0])
		})
	}
}
