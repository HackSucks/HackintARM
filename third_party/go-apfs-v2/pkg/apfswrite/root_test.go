package apfswrite_test

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
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/imagesecurity"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/securitycopy"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func TestRootMetadataImages(t *testing.T) {
	b, e := os.ReadFile("../../testdata/appledouble/native/image-root-security.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	z, e := gzip.NewReader(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var fixture imagesecurity.Fixture
	if e = json.NewDecoder(z).Decode(&fixture); e != nil {
		t.Fatal(e)
	}
	if len(fixture.Cases) != 26 || len(fixture.Images) != 26 || len(fixture.NativeXattrs) != 26 {
		t.Fatal("incomplete native root corpus")
	}
	helper, e := os.ReadFile("../../testdata/appledouble/native/image-security.c")
	if e != nil {
		t.Fatal(e)
	}
	helper = bytes.ReplaceAll(helper, []byte("\r\n"), []byte("\n"))
	if fmt.Sprintf("%x", sha256.Sum256(helper)) != fixture.HelperSHA256 {
		t.Fatal("native helper provenance")
	}
	observed := map[string]imagesecurity.NativeCase{}
	for _, c := range fixture.Cases {
		if _, ok := observed[c.Filesystem]; ok {
			t.Fatal("duplicate root case")
		}
		observed[c.Filesystem] = c
	}

	for _, sensitive := range []bool{false, true} {
		for _, profile := range imagesecurity.Roots(fixture.ActorUID, fixture.ActorGID) {
			t.Run(profile.Name+map[bool]string{true: "-sensitive", false: "-folded"}[sensitive], func(t *testing.T) {
				file, e := os.Create(filepath.Join(t.TempDir(), "root.img"))
				if e != nil {
					t.Fatal(e)
				}
				defer file.Close()
				before, e := json.Marshal(profile.Root)
				if e != nil {
					t.Fatal(e)
				}
				opts := &apfswrite.CreateOptions{Root: profile.Root, VolumeName: "ROOT", CaseSensitive: sensitive, Snapshots: profile.Snapshots}
				if e = apfswrite.CreateContainer(file, 64<<20, opts); e != nil {
					t.Fatal(e)
				}
				after, e := json.Marshal(profile.Root)
				if e != nil || !bytes.Equal(before, after) {
					t.Fatal("caller root modified")
				}
				container, e := apfs.Open(file, nil)
				if e != nil {
					t.Fatal(e)
				}
				vols, e := container.Volumes()
				if e != nil || len(vols) != 1 {
					t.Fatal("volume count", e)
				}
				v := vols[0]
				got, e := v.Security(".")
				if e != nil {
					t.Fatal(e)
				}
				want := profile.Case
				kind := "apfs"
				if sensitive {
					kind = "apfs-sensitive"
				}
				key := kind + "-" + profile.Name
				native, ok := observed[key]
				if !ok {
					t.Fatal("missing native case " + key)
				}
				n := native.Native
				if native.Case != want || n.Code != 0 || n.ReferenceCode != 0 || n.Errno != 0 || n.ReferenceErrno != 0 || !n.SameIdentity || !reflect.DeepEqual(n.Properties, n.ReferenceProperties) || !reflect.DeepEqual(securitycopy.PropertiesFromGo(got.Source.Properties), n.Properties) {
					t.Fatal("native security mismatch: " + key)
				}
				raw := fixture.NativeXattrs[key]
				if len(raw) != len(profile.Root.Xattrs) {
					t.Fatal("native attribute count")
				}
				for name, value := range profile.Root.Xattrs {
					o, ok := raw[name]
					if !ok {
						t.Fatal("missing native attribute " + name)
					}
					wantErr := 0
					switch {
					case profile.Name == "owner-mode":
						wantErr = 13
					case name == "com.apple.system.Security":
						wantErr = 1
					case name == "com.apple.ResourceFork":
						wantErr = 93
					}
					if o.Errno != wantErr {
						t.Fatal("native attribute errno", name, o.Errno, wantErr)
					}
					if wantErr != 0 {
						if o.Length != -1 || o.Value != nil {
							t.Fatal("refusal returned value")
						}
					} else if o.Value == nil || o.Length != len(value) || *o.Value != fmt.Sprintf("%x", value) {
						t.Fatal("native attribute bytes", name)
					}
				}

				if got.Source.UID != want.UID || got.Source.GID != want.GID || got.Source.Mode != uint32(want.Mode) || got.Disposition != want.Disposition {
					t.Fatalf("root security: %+v want %+v", got, want)
				}
				attrs, e := v.Xattrs(".")
				if e != nil || len(attrs) != len(profile.Root.Xattrs) {
					t.Fatal("root attribute count", e)
				}
				for name, value := range profile.Root.Xattrs {
					a, ok := attrs[name]
					if !ok || !bytes.Equal(a, value) {
						t.Fatal("root attribute bytes: " + name)
					}
				}
				fe, e := v.FileEntryByPath("/")
				if e != nil {
					t.Fatal(e)
				}
				stamp := profile.Root.ModTime
				if stamp.IsZero() {
					stamp = apfswrite.DefaultTime
				}
				for _, nativeTime := range n.Times {
					if nativeTime != stamp.UnixNano() {
						t.Fatal("native root timestamp", nativeTime, stamp)
					}
				}
				if fe.Inode.Identifier != 2 || fe.Inode.ParentIdentifier != 1 || fe.Inode.ModificationTime != uint64(stamp.UnixNano()) {
					t.Fatalf("root identity/time: %+v", fe.Inode)
				}
				entries, e := fs.ReadDir(v, ".")
				if e != nil || len(entries) != len(profile.Root.Children) {
					t.Fatal("root child count", e)
				}
				for _, child := range profile.Root.Children {
					if child.Mode.IsDir() {
						continue
					}
					b, e := fs.ReadFile(v, child.Name)
					if e != nil || !bytes.Equal(b, child.Data) {
						t.Fatalf("child payload: %s %v", child.Name, e)
					}
				}
				snapshotCount, e := v.NumberOfSnapshots()
				if e != nil || snapshotCount != len(profile.Snapshots) {
					t.Fatal("snapshot count", snapshotCount, e)
				}
			})
		}
	}
}

func TestRootMetadataValidation(t *testing.T) {
	for _, root := range []*apfswrite.Entry{
		{Mode: os.ModeSymlink}, {Mode: os.ModeNamedPipe}, {Mode: os.ModeDevice},
		{DataValue: bytes.NewReader(nil)},
		{Xattrs: map[string][]byte{"": {1}}}, {Xattrs: map[string][]byte{"bad\x00name": {1}}},
		{Xattrs: map[string][]byte{"com.apple.fs.symlink": []byte("target")}},
		{Xattrs: map[string][]byte{"com.apple.decmpfs": {1}}},
	} {
		if e := apfswrite.CreateContainer(&memImage{}, 64<<20, &apfswrite.CreateOptions{Root: root}); e == nil {
			t.Fatalf("invalid root accepted: %+v", root)
		}
	}
	// Name, payload and link-group never create a user inode for the root.
	plain := buildImage(t, &apfswrite.CreateOptions{Root: &apfswrite.Entry{}})
	ignored := buildImage(t, &apfswrite.CreateOptions{Root: &apfswrite.Entry{Name: "ignored/\x00", Data: []byte("ignored"), LinkGroup: 9}})
	if !bytes.Equal(plain, ignored) {
		t.Fatal("ignored root fields altered image")
	}
	if !bytes.Equal(plain, buildImage(t, nil)) {
		t.Fatal("default root changed image")
	}
}

func TestRootMetadataClocksAndRootFiles(t *testing.T) {
	v := openVolume(t, &apfswrite.CreateOptions{RootFiles: []apfswrite.RootFile{{Name: "plain", Data: []byte("plain")}}})
	if s, e := v.Security("."); e != nil || s.Source.UID != 0 || s.Source.Mode != 040755 {
		t.Fatal("default root with shorthand file", e)
	}
	fixed := time.Unix(1600000000, 0)
	for _, clamp := range []bool{false, true} {
		root := &apfswrite.Entry{Mode: 0711, UID: 42, GID: 43, ModTime: fixed.Add(time.Hour)}
		v := openVolume(t, &apfswrite.CreateOptions{Root: root, FixedTime: fixed, ClampModTimes: clamp, RootFiles: []apfswrite.RootFile{{Name: "f", Data: []byte("payload")}}})
		want := root.ModTime
		if clamp {
			want = fixed
		}
		assertModTime(t, v, ".", want)
		s, e := v.Security(".")
		if e != nil || s.Source.Mode != 040711 || s.Source.UID != 42 {
			t.Fatal("root metadata with shorthand file", e)
		}
		b, e := v.ReadFile("f")
		if e != nil || string(b) != "payload" {
			t.Fatal("RootFiles lost", e)
		}
	}
}

func TestRootMetadataMultipleVolumes(t *testing.T) {
	roots := imagesecurity.Roots(501, 20)
	first, second := roots[6].Root, roots[9].Root
	img, err := os.Create(filepath.Join(t.TempDir(), "multi.img"))
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	opts := &apfswrite.CreateOptions{Volumes: []apfswrite.VolumeSpec{{Name: "FIRST", Root: first}, {Name: "SECOND", Root: second, CaseSensitive: true, Snapshots: roots[9].Snapshots}}}
	if e := apfswrite.CreateContainer(img, 1024<<20, opts); e != nil {
		t.Fatal(e)
	}
	c, e := apfs.Open(img, nil)
	if e != nil {
		t.Fatal(e)
	}
	vols, e := c.Volumes()
	if e != nil || len(vols) != 2 {
		t.Fatal("volume count", e)
	}
	for i, root := range []*apfswrite.Entry{first, second} {
		attrs, e := vols[i].Xattrs(".")
		if e != nil || !reflect.DeepEqual(attrs, root.Xattrs) {
			t.Fatalf("volume %d metadata crossed volumes: %v", i, e)
		}
	}
}

func TestRootMetadataInvalidTimes(t *testing.T) {
	file, e := os.Create(filepath.Join(t.TempDir(), "invalid.img"))
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	root := &apfswrite.Entry{Times: &hostdata.FileTimes{}}
	if e = apfswrite.CreateContainer(file, 64<<20, &apfswrite.CreateOptions{Root: root}); !errors.Is(e, fs.ErrInvalid) {
		t.Fatal(e)
	}
	info, e := file.Stat()
	if e != nil || info.Size() != 0 {
		t.Fatal("wrote before validation", e)
	}
}
