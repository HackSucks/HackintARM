package hostdata

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

func TestReplacementOptions(t *testing.T) {
	for _, profile := range []osversion.MacOSProfile{0, osversion.MacOS15, osversion.MacOS26, osversion.MacOS27, 14, 28} {
		for _, rooted := range []bool{false, true} {
			t.Run(profileName(profile, rooted), func(t *testing.T) {
				directory := t.TempDir()
				root, err := os.OpenRoot(directory)
				if err != nil {
					t.Fatal(err)
				}
				defer root.Close()
				source, err := root.OpenFile("input", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
				if err != nil {
					t.Fatal(err)
				}
				defer source.Close()
				if _, err := source.Write([]byte("unchanged")); err != nil {
					t.Fatal(err)
				}
				options := ReplacementOptions{MacOSProfile: profile}
				for _, canceled := range []bool{false, true} {
					ctx, cancel := context.WithCancel(t.Context())
					if canceled {
						cancel()
					}
					var close func() error
					if rooted {
						var replacement *RootReplacement
						replacement, err = PrepareReplacementAtWithOptionsContext(ctx, source, root, ".", options)
						if replacement != nil {
							close = replacement.Close
						}
					} else {
						var replacement *Replacement
						replacement, err = PrepareReplacementWithOptionsContext(ctx, source, directory, options)
						if replacement != nil {
							close = replacement.Close
						}
					}
					cancel()
					var expected error
					if canceled {
						expected = context.Canceled
					} else if profile == 14 || profile == 28 {
						expected = osversion.ErrMacOSProfile
					}
					if !errors.Is(err, expected) {
						t.Fatal("wrong options outcome", err, expected)
					}
					if close != nil {
						if err := close(); err != nil {
							t.Fatal(err)
						}
					}
					entries, err := os.ReadDir(directory)
					if err != nil || len(entries) != 1 {
						t.Fatal("staging leak", err, entries)
					}
					content, err := os.ReadFile(filepath.Join(directory, "input"))
					if err != nil || string(content) != "unchanged" {
						t.Fatal("source changed", err)
					}
				}
			})
		}
	}
}
func profileName(profile osversion.MacOSProfile, rooted bool) string {
	// Small names keep every explicit API/profile pair visible in CI.
	name := map[osversion.MacOSProfile]string{0: "default", 15: "macos15", 26: "macos26", 27: "macos27", 14: "unsupported14", 28: "unsupported28"}[profile]
	if rooted {
		return name + "/root"
	}
	return name + "/path"
}

func TestReplacementFilesystemMacOSProfiles(t *testing.T) {
	for _, profile := range []osversion.MacOSProfile{osversion.MacOS15, osversion.MacOS26, osversion.MacOS27} {
		t.Run(profileName(profile, true), func(t *testing.T) {
			directory := t.TempDir()
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			source, err := root.OpenFile("input", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			target, err := root.OpenFile("staged", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			metadata := &appledouble.StreamFile{FinderInfo: [32]byte{1}, ResourceFork: bytes.NewReader([]byte{0x6b}), Attrs: []appledouble.StreamAttr{{Name: "com.example.retained", Value: bytes.NewReader([]byte("native-value"))}}}
			var packed bytes.Buffer
			if _, err := metadata.EncodeTo(t.Context(), &packed, appledouble.DefaultStreamLimits()); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, "._input"), packed.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			state, err := prepareReplacementFilesystemUsingForProfile(t.Context(), source, target, replacementTestFilesystemView, profile)
			if profile != osversion.MacOS15 {
				if state != nil || !errors.Is(err, syscall.EINVAL) {
					t.Fatal("newer native rejection lost", state, err)
				}
				if _, err := root.Lstat("._staged"); !os.IsNotExist(err) {
					t.Fatal("failed profile published a carrier", err)
				}
			} else {
				if state == nil || err != nil {
					t.Fatal("macOS 15 acceptance lost", err)
				}
				content, err := os.ReadFile(filepath.Join(directory, "._staged"))
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := appledouble.DecodeFilesystemStream(t.Context(), bytes.NewReader(content), appledouble.DefaultStreamLimits())
				if err != nil {
					t.Fatal(err)
				}
				if decoded.ResourceFork == nil || decoded.ResourceFork.Size() != 1 {
					t.Fatal("accepted short fork lost")
				}
				fork := []byte{0}
				if count, err := decoded.ResourceFork.ReadAt(fork, 0); count != 1 || (err != nil && !errors.Is(err, io.EOF)) || fork[0] != 0x6b {
					t.Fatal("fork changed", err)
				}
			}
			content, err := os.ReadFile(filepath.Join(directory, "._input"))
			if err != nil || !bytes.Equal(content, packed.Bytes()) {
				t.Fatal("profile altered source", err)
			}
		})
	}
}
