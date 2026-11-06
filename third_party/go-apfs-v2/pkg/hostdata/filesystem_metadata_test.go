package hostdata

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestFilesystemMetadataNativeFATReadback(t *testing.T) {
	type entry struct {
		Mode  uint32
		Bytes []byte
	}
	type query struct {
		Attributes []struct {
			Name      string
			Size      int64
			SizeErrno int `json:"size_errno"`
			ReadErrno int `json:"read_errno"`
			Bytes     string
		}
		ListBytes string `json:"list_bytes"`
		ListErrno int    `json:"list_errno"`
	}
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
				z, err := gzip.NewReader(f)
				if err != nil {
					t.Fatal(err)
				}
				defer z.Close()
				reader = z
			}
			var c struct {
				Complete bool
				Profile  string
				Cases    []struct {
					ID            string
					Before, After map[string]entry
					Observation   struct {
						Before query `json:"before_held"`
						After  query `json:"after_held"`
					}
				}
			}
			if err = json.NewDecoder(reader).Decode(&c); err != nil {
				t.Fatal(err)
			}
			if !c.Complete || len(c.Cases) != profile.Cases || c.Profile != profile.Profile {
				t.Fatal("incomplete native producer")
			}
			tested := 0
			for _, r := range c.Cases {
				if !strings.HasPrefix(r.ID, "ExFAT/") && !strings.HasPrefix(r.ID, "MS-DOS FAT32/") {
					continue
				}
				for _, stage := range []struct {
					name  string
					tree  map[string]entry
					query query
				}{{"before", r.Before, r.Observation.Before}, {"after", r.After, r.Observation.After}} {
					t.Run(r.ID+"/"+stage.name, func(t *testing.T) {
						dir := t.TempDir()
						for name, e := range stage.tree {
							path := filepath.Join(dir, name)
							if os.FileMode(e.Mode).IsDir() {
								err = os.Mkdir(path, 0755)
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
						names, err := view.List(context.Background(), MaxXattrListSize)
						if stage.query.ListErrno == 1 {
							if !errors.Is(err, syscall.EPERM) {
								t.Fatal("expected native EPERM list result", err)
							}
						} else if stage.query.ListErrno == 93 {
							if !errors.Is(err, ErrXattrNotFound) {
								t.Fatal("expected native ENOATTR list result", err)
							}
						} else if err != nil || stage.query.ListErrno != 0 {
							t.Fatal("native list error mismatch", stage.query.ListErrno, err)
						}
						raw := ""
						for _, name := range names {
							raw += name + "\x00"
						}
						if hex.EncodeToString([]byte(raw)) != stage.query.ListBytes {
							t.Fatalf("native names %s, Go %x", stage.query.ListBytes, raw)
						}
						for _, a := range stage.query.Attributes {
							size, exists, sizeErr := view.Size(context.Background(), a.Name)
							if a.SizeErrno == 1 {
								if !errors.Is(sizeErr, syscall.EPERM) || exists || size != 0 {
									t.Fatal("expected native EPERM size result", a.Name, size, exists, sizeErr)
								}
							} else if sizeErr != nil || exists != (a.SizeErrno == 0) || size != max(a.Size, 0) {
								t.Fatalf("%s: native size=%d errno=%d; Go size=%d present=%v err=%v", a.Name, a.Size, a.SizeErrno, size, exists, sizeErr)
							}
							value, present, err := view.Read(context.Background(), a.Name, 65536)
							if a.ReadErrno == 1 {
								if !errors.Is(err, syscall.EPERM) || present || len(value) != 0 {
									t.Fatal("expected native EPERM read result", a.Name, present, value, err)
								}
								continue
							}
							if err != nil {
								t.Fatal(a.Name, err)
							}
							if present != (a.ReadErrno == 0) || int64(len(value)) != max(a.Size, 0) || hex.EncodeToString(value) != a.Bytes {
								t.Fatalf("%s: native size=%d errno=%d bytes=%s; Go present=%v value=%x", a.Name, a.Size, a.ReadErrno, a.Bytes, present, value)
							}
						}
					})
					tested++
				}
			}
			if tested != profile.Cases {
				t.Fatalf("lost FAT snapshots: %d", tested)
			}
		})
	}
}

func newMetadataTestView(t *testing.T, sidecar bool) (*FilesystemMetadata, *os.Root, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "input"), []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	view, err := openFilesystemMetadata(context.Background(), root, "input", func(*os.File) (bool, error) { return sidecar, nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { view.Close() })
	return view, root, dir
}

func TestFilesystemMetadataScope(t *testing.T) {
	v, root, dir := newMetadataTestView(t, true)
	seed, err := readMetadataViewSeed()
	if err != nil {
		t.Fatal(err)
	}
	if err = root.WriteFile("._input", seed, 0600); err != nil {
		t.Fatal(err)
	}
	value, present, err := v.OpenValue(context.Background(), ResourceForkName)
	if err != nil || !present {
		t.Fatal(present, err)
	}
	if err = root.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err = v.Read(context.Background(), ResourceForkName, 1); !errors.Is(err, ErrXattrTooLarge) {
		t.Fatal(err)
	}
	if _, err = v.List(context.Background(), 0); !errors.Is(err, ErrXattrTooLarge) {
		t.Fatal(err)
	}
	for _, name := range []string{"", "bad\x00name"} {
		if _, _, err = v.OpenValue(context.Background(), name); !errors.Is(err, os.ErrInvalid) {
			t.Fatal(err)
		}
	}
	if _, err = v.List(context.Background(), -1); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if _, _, err = v.Read(context.Background(), ResourceForkName, -1); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = v.List(ctx, 100); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, _, err = v.OpenValue(ctx, ResourceForkName); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err = v.Close(); err != nil {
		t.Fatal(err)
	}
	if err = v.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = v.List(context.Background(), 100); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	b := make([]byte, value.Size())
	if _, err = value.ReadAt(b, 0); err != nil || string(b) != "native-value" {
		t.Fatal(string(b), err)
	}
	if _, err = value.ReadAt(b, -1); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if err = value.Close(); err != nil {
		t.Fatal(err)
	}
	if err = value.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = value.ReadAt(b, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(dir, "input")); err != nil {
		t.Fatal(err)
	}
}

func readMetadataViewSeed() ([]byte, error) {
	f, e := os.Open("../../testdata/appledouble/native/metadata-filesystem-macos27.json.gz")
	if e != nil {
		return nil, e
	}
	defer f.Close()
	z, e := gzip.NewReader(f)
	if e != nil {
		return nil, e
	}
	defer z.Close()
	var capture struct{ Seed []byte }
	e = json.NewDecoder(z).Decode(&capture)
	return capture.Seed, e
}

func TestFilesystemMetadataIdentityAndSelection(t *testing.T) {
	v, root, _ := newMetadataTestView(t, true)
	if err := root.Rename("input", "original"); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("input", []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.List(context.Background(), 100); !errors.Is(err, ErrMetadataIdentity) {
		t.Fatal(err)
	}
	for _, name := range []string{"../outside", "missing"} {
		if got, err := OpenFilesystemMetadata(context.Background(), root, name); err == nil {
			got.Close()
			t.Fatal("invalid open succeeded")
		}
	}
	if got, err := openFilesystemMetadata(context.Background(), root, "input", func(*os.File) (bool, error) { return false, io.ErrUnexpectedEOF }); got != nil || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := OpenFilesystemMetadata(ctx, root, "input"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	native, err := OpenFilesystemMetadata(context.Background(), root, "input")
	if err != nil {
		t.Fatal(err)
	}
	defer native.Close()
	// The ordinary test filesystem is not FAT. A packed neighbor must not be
	// reinterpreted by the native host provider, even when it is well formed.
	seed, err := readMetadataViewSeed()
	if err != nil {
		t.Fatal(err)
	}
	if err = root.WriteFile("._input", seed, 0600); err != nil {
		t.Fatal(err)
	}
	if b, present, err := native.Read(context.Background(), "com.example.phase2", 64); present || (err != nil && !errors.Is(err, ErrXattrUnsupported)) {
		t.Fatal(b, present, err)
	}
}

func TestMetadataValueCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	v := &MetadataValue{ctx: ctx, value: bytes.NewReader([]byte("value"))}
	cancel()
	if _, err := v.ReadAt(make([]byte, 1), 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
}

// This is a format-width/storage boundary, not a synthesized native observation.
// It must remain sparse on Windows too: a dense fixture would test disk capacity.
func TestFilesystemMetadataLargeFork(t *testing.T) {
	v, root, _ := newMetadataTestView(t, true)
	seed, err := readMetadataViewSeed()
	if err != nil {
		t.Fatal(err)
	}
	var forkOffset int64
	for i := 0; i < int(binary.BigEndian.Uint16(seed[24:26])); i++ {
		descriptor := seed[26+i*12 : 38+i*12]
		if binary.BigEndian.Uint32(descriptor[:4]) == 2 {
			forkOffset = int64(binary.BigEndian.Uint32(descriptor[4:8]))
			binary.BigEndian.PutUint32(descriptor[8:12], math.MaxUint32)
		}
	}
	if forkOffset <= 0 {
		t.Fatal("native seed lacks fork descriptor")
	}
	file, err := root.OpenFile("._input", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err = replacementSparse(file); err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write(seed); err != nil {
		t.Fatal(err)
	}
	if err = file.Truncate(forkOffset + math.MaxUint32); err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int64{1<<31 - 1, 1 << 31, math.MaxUint32 - 1} {
		if _, err = file.WriteAt([]byte{0x5a}, forkOffset+offset); err != nil {
			t.Fatal(err)
		}
	}
	value, present, err := v.OpenValue(context.Background(), ResourceForkName)
	if err != nil || !present {
		t.Fatal(present, err)
	}
	defer value.Close()
	if value.Size() != math.MaxUint32 {
		t.Fatal(value.Size())
	}
	for _, offset := range []int64{1<<31 - 1, 1 << 31, math.MaxUint32 - 1} {
		b := make([]byte, 1)
		if n, err := value.ReadAt(b, offset); err != nil || n != 1 || b[0] != 0x5a {
			t.Fatal(offset, n, b, err)
		}
	}
	if n, err := value.ReadAt(make([]byte, 2), math.MaxUint32-1); n != 1 || !errors.Is(err, io.EOF) {
		t.Fatal(n, err)
	}
	if n, err := value.ReadAt(make([]byte, 1), math.MaxUint32); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatal(n, err)
	}
	if _, _, err := v.Read(context.Background(), ResourceForkName, 65536); !errors.Is(err, ErrXattrTooLarge) {
		t.Fatal(err)
	}
}
