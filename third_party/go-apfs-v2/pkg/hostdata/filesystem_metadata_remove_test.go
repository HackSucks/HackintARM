package hostdata

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestFilesystemMetadataNativeFATRemoval(t *testing.T) {
	for _, profile := range filesystemMetadataCorpora() {
		t.Run(profile.Name, func(t *testing.T) {
			path := profile.Path
			fresh := os.Getenv("APFS_METADATA_FILESYSTEM_PRODUCERS")
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			var reader io.Reader = f
			if fresh == "" {
				z, e := gzip.NewReader(f)
				if e != nil {
					t.Fatal(e)
				}
				defer z.Close()
				reader = z
			}
			type entry struct {
				Mode  uint32
				Bytes []byte
			}
			var corpus struct {
				Complete bool
				Profile  string
				Cases    []struct {
					ID            string
					Before, After map[string]entry
					Observation   struct{ Result, Errno int }
				}
			}
			if err = json.NewDecoder(reader).Decode(&corpus); err != nil {
				t.Fatal(err)
			}
			if !corpus.Complete || len(corpus.Cases) != profile.Cases || corpus.Profile != profile.Profile {
				t.Fatal("incomplete native producer")
			}
			tested := 0
			for _, c := range corpus.Cases {
				parts := strings.Split(c.ID, "/")
				if len(parts) != 4 || (parts[0] != "ExFAT" && parts[0] != "MS-DOS FAT32") {
					continue
				}
				name := map[string]string{"remove": "com.example.phase2", "remove-finder": "com.apple.FinderInfo", "remove-fork": ResourceForkName}[parts[3]]
				if name == "" {
					continue
				}
				tested++
				t.Run(c.ID, func(t *testing.T) {
					dir := t.TempDir()
					for name, e := range c.Before {
						path := filepath.Join(dir, name)
						if os.FileMode(e.Mode).IsDir() {
							err = os.Mkdir(path, 0700)
						} else {
							err = os.WriteFile(path, e.Bytes, 0600)
						}
						if err != nil {
							t.Fatal(err)
						}
					}
					root, err := os.OpenRoot(dir)
					if err != nil {
						t.Fatal(err)
					}
					defer root.Close()
					view, err := openFilesystemMetadata(context.Background(), root, profile.target(), func(*os.File) (bool, error) { return true, nil })
					if err != nil {
						t.Fatal(err)
					}
					defer view.Close()
					removed, err := view.Remove(context.Background(), name)
					if c.Observation.Errno == 1 {
						if !errors.Is(err, syscall.EPERM) || removed || c.Observation.Result != -1 {
							t.Fatalf("expected native EPERM removal: removed=%v err=%v", removed, err)
						}
					} else if err != nil || removed != (c.Observation.Result == 0) || (c.Observation.Result != 0 && c.Observation.Errno != 93) {
						t.Fatalf("removed=%v err=%v; native result=%d errno=%d", removed, err, c.Observation.Result, c.Observation.Errno)
					}
					entries, err := os.ReadDir(dir)
					if err != nil {
						t.Fatal(err)
					}
					if len(entries) != len(c.After) {
						t.Fatalf("entry count got %d want %d", len(entries), len(c.After))
					}
					for _, e := range entries {
						expected, ok := c.After[e.Name()]
						if !ok {
							t.Fatal("unexpected entry", e.Name())
						}
						if e.IsDir() != os.FileMode(expected.Mode).IsDir() {
							t.Fatal("entry type changed", e.Name())
						}
						if e.IsDir() {
							continue
						}
						actual, err := root.ReadFile(e.Name())
						if err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(actual, expected.Bytes) {
							t.Fatalf("%s: native bytes differ:\nwant %x\n got %x", e.Name(), expected.Bytes, actual)
						}
					}
				})
			}
			if tested != profile.Cases/8 {
				t.Fatalf("lost removal cases: got %d want %d", tested, profile.Cases/8)
			}
		})
	}
}

func TestFilesystemMetadataRemovalBoundaries(t *testing.T) {
	v, root, _ := newMetadataTestView(t, true)
	ctx := context.Background()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := v.Remove(canceled, "attr"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := v.Remove(ctx, ""); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if err := root.Remove("input"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Remove(ctx, "attr"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Remove(ctx, "attr"); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}

func TestFilesystemMetadataRemovalFailures(t *testing.T) {
	for _, scenario := range []string{"open", "closed-writer", "substituted-writer", "partial-write", "cancel-unlink", "substituted-unlink", "missing-unlink", "unlink-error"} {
		t.Run(scenario, func(t *testing.T) {
			v, root, _ := newMetadataTestView(t, true)
			raw, err := (&appledouble.File{Attrs: []appledouble.Attr{{Name: "only", Value: []byte("data")}}}).Encode()
			if err != nil {
				t.Fatal(err)
			}
			if err = root.WriteFile("._input", raw, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			originalWriter := v.ops.writer
			originalRemove := v.ops.remove
			want := io.ErrClosedPipe
			switch scenario {
			case "open":
				v.ops.writer = func(*os.Root, string) (*os.File, error) { return nil, want }
			case "closed-writer":
				want = os.ErrClosed
				v.ops.writer = func(r *os.Root, n string) (*os.File, error) {
					f, e := originalWriter(r, n)
					if e == nil {
						e = f.Close()
					}
					return f, e
				}
			case "substituted-writer":
				want = ErrMetadataIdentity
				v.ops.writer = func(r *os.Root, _ string) (*os.File, error) { return r.OpenFile("input", os.O_RDWR, 0) }
			case "partial-write":
				v.ops.remove = func(_ context.Context, f appledouble.AttributeFile, _ string) (appledouble.AttributeRemoval, error) {
					if _, e := f.WriteAt([]byte{0}, 0); e != nil {
						t.Fatal(e)
					}
					return appledouble.AttributeRemoval{}, want
				}
			case "cancel-unlink":
				want = context.Canceled
				v.ops.remove = func(ctx context.Context, f appledouble.AttributeFile, name string) (appledouble.AttributeRemoval, error) {
					result, e := originalRemove(ctx, f, name)
					cancel()
					return result, e
				}
			case "substituted-unlink", "missing-unlink":
				want = ErrMetadataIdentity
				if scenario == "missing-unlink" {
					want = os.ErrNotExist
				}
				v.ops.remove = func(ctx context.Context, f appledouble.AttributeFile, name string) (appledouble.AttributeRemoval, error) {
					result, e := originalRemove(ctx, f, name)
					if err := root.Rename("._input", "original"); err != nil {
						t.Fatal(err)
					}
					if scenario == "substituted-unlink" {
						if err := root.WriteFile("._input", []byte("replacement"), 0600); err != nil {
							t.Fatal(err)
						}
					}
					return result, e
				}
			case "unlink-error":
				v.ops.unlink = func(*os.Root, string) error { return want }
			}
			if removed, err := v.Remove(ctx, "only"); removed || !errors.Is(err, want) {
				t.Fatal(removed, err, want)
			}
			if scenario == "substituted-unlink" {
				b, err := root.ReadFile("._input")
				if err != nil || string(b) != "replacement" {
					t.Fatal("replacement removed", string(b), err)
				}
			}
			if scenario == "partial-write" {
				b, err := root.ReadFile("._input")
				if err != nil || b[0] != 0 {
					t.Fatal("partial write lost", err)
				}
			}
		})
	}
}

func TestFilesystemMetadataRemovalLastAttribute(t *testing.T) {
	v, root, _ := newMetadataTestView(t, true)
	raw, err := (&appledouble.File{FinderInfo: [32]byte{1}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err = root.WriteFile("._input", raw, 0600); err != nil {
		t.Fatal(err)
	}
	if removed, err := v.Remove(context.Background(), "com.apple.FinderInfo"); err != nil || !removed {
		t.Fatal(removed, err)
	}
	if _, err = root.Stat("._input"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if b, err := root.ReadFile("input"); err != nil || string(b) != "payload" {
		t.Fatal(string(b), err)
	}
}

func TestFilesystemMetadataNativeRemoval(t *testing.T) {
	v, _, _ := newMetadataTestView(t, false)
	ctx := context.Background()
	const name = "user.filesystem-removal"
	if err := SetXattr(v.file, name, []byte("data")); err != nil {
		t.Fatal(err)
	}
	if removed, err := v.Remove(ctx, name); err != nil || !removed {
		t.Fatal(removed, err)
	}
	if removed, err := v.Remove(ctx, name); err != nil || removed {
		t.Fatal(removed, err)
	}
}
