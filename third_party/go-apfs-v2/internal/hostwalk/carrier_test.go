package hostwalk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/fidelity"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

type carrierNode struct {
	Node
	Children []*carrierNode
}

func makeCarrierNode(n Node, c []*carrierNode) *carrierNode { return &carrierNode{n, c} }
func emptyCapture(context.Context, string, hostdata.XattrCaptureLimits) (map[string][]byte, error) {
	return map[string][]byte{}, nil
}
func carrierFixture(t *testing.T) (string, string, *metatransport.Store) {
	t.Helper()
	base := t.TempDir()
	p, m := filepath.Join(base, "payload"), filepath.Join(base, "metadata")
	os.Mkdir(p, 0700)
	os.Mkdir(m, 0700)
	s, e := metatransport.Open(p, m, metatransport.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return p, m, s
}
func carrierRef(b []byte) *metatransport.BlobRef {
	h := sha256.Sum256(b)
	return &metatransport.BlobRef{SHA256: hex.EncodeToString(h[:]), Size: int64(len(b))}
}
func carrierFile(t *testing.T, p, materialized, original string) metatransport.Record {
	t.Helper()
	b := []byte("payload")
	if e := os.WriteFile(filepath.Join(p, materialized), b, 0600); e != nil {
		t.Fatal(e)
	}
	return metatransport.Record{Original: original, Materialized: materialized, Kind: "file", MaterializedKind: "file", Payload: carrierRef(b)}
}
func commitCarrier(t *testing.T, s *metatransport.Store, r []metatransport.Record) {
	t.Helper()
	if e := s.Commit(context.Background(), metatransport.Manifest{Version: 1, Records: r}, 0); e != nil {
		t.Fatal(e)
	}
}
func attrsCarrier(t *testing.T, s *metatransport.Store, values map[string][]byte) []metatransport.Attribute {
	t.Helper()
	a, e := s.StoreAttributes(context.Background(), values)
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func TestCarrierWalkPreservesTree(t *testing.T) {
	p, m, s := carrierFixture(t)
	file := carrierFile(t, p, "remapped", "original:é")
	second := carrierFile(t, p, "alias", "alias")
	file.LinkGroup = "g"
	second.LinkGroup = "g"
	mode, uid, gid, flags := uint32(0106750), uint32(42), uint32(43), uint32(0)
	birth := time.Unix(100, 0)
	modify := time.Unix(200, 0)
	change := time.Unix(300, 0)
	access := time.Unix(400, 0)
	state := metatransport.DarwinState{Mode: &mode, UID: &uid, GID: &gid, Flags: &flags, Birth: &birth, Modify: &modify, Change: &change, Access: &access}
	file.Darwin = state
	second.Darwin = state
	attrs := attrsCarrier(t, s, map[string][]byte{"case": {1}, "Case": {}, "com.apple.ResourceFork": {1, 2, 3}})
	file.Attributes = attrs
	second.Attributes = attrs
	link := carrierFile(t, p, "degraded", "link")
	link.Kind = "symlink"
	link.Target = "original:é"
	os.WriteFile(filepath.Join(p, "degraded"), []byte(link.Target), 0600)
	link.Payload = carrierRef([]byte(link.Target))
	os.Mkdir(filepath.Join(p, "dir"), 0700)
	dir := metatransport.Record{Original: "directory", Materialized: "dir", Kind: "directory", MaterializedKind: "directory"}
	child := carrierFile(t, filepath.Join(p, "dir"), "child", "directory/child")
	child.Materialized = "dir/child"
	root := metatransport.Record{Original: ".", Materialized: ".", Kind: "directory", MaterializedKind: "directory"}
	zero := uint32(0)
	root.Darwin.Mode = &zero
	root.Darwin.UID = &uid
	root.Darwin.Birth = &birth
	root.Darwin.Modify = &modify
	root.Darwin.Change = &change
	root.Darwin.Access = &access
	os.WriteFile(filepath.Join(p, "._ordinary"), []byte("user data"), 0600)
	commitCarrier(t, s, []metatransport.Record{root, file, second, link, dir, child})
	got, report, e := Walk(p, &Options{MetadataRoot: m, HardLinks: true, Compression: true}, makeCarrierNode)
	if e != nil {
		t.Fatal(e)
	}
	if got.Name != "" || got.Mode.Perm() != 0 || !got.ModeExplicit || got.Times == nil || !got.Times.Change.Equal(change) || got.UID != uid {
		t.Fatalf("root %#v", got)
	}
	if report.Count(fidelity.Xattr) != 0 {
		t.Fatal(report)
	}
	nodes := map[string]*carrierNode{}
	for _, n := range got.Children {
		nodes[n.Name] = n
	}
	if string(nodes["._ordinary"].Data) != "user data" {
		t.Fatal("ordinary sidecar-name file lost")
	}
	if nodes["link"].Mode&os.ModeSymlink == 0 || string(nodes["link"].Data) != link.Target {
		t.Fatal("degraded link not restored")
	}
	if nodes["original:é"].LinkGroup == 0 || nodes["original:é"].LinkGroup != nodes["alias"].LinkGroup {
		t.Fatal("alias groups")
	}
	if !reflect.DeepEqual(nodes["original:é"].Xattrs, nodes["alias"].Xattrs) {
		t.Fatal("alias attributes")
	}
	if nodes["directory"].Children[0].Name != "child" {
		t.Fatal("parent mapping")
	}
}
func TestCarrierWalkConflicts(t *testing.T) {
	cases := []string{"orphan", "parent", "collision", "kind", "hardlink-unsupported", "hardlink-changed", "native-conflict", "capture-error", "keep-refused", "budget", "cancel", "missing-root", "invalid-mode", "wrong-mode"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			p, m, s := carrierFixture(t)
			r := carrierFile(t, p, "file", "file")
			r.Attributes = attrsCarrier(t, s, map[string][]byte{"case": {1}})
			records := []metatransport.Record{r}
			opts := &Options{MetadataRoot: m, HardLinks: true}
			capture := emptyCapture
			switch name {
			case "orphan":
				os.Remove(filepath.Join(p, "file"))
			case "parent":
				records[0].Original = "other/file"
			case "collision":
				records[0].Original = "other"
				os.WriteFile(filepath.Join(p, "other"), nil, 0600)
			case "kind":
				os.Remove(filepath.Join(p, "file"))
				os.Mkdir(filepath.Join(p, "file"), 0700)
			case "hardlink-unsupported":
				records[0].LinkGroup = "g"
				opts.HardLinks = false
			case "hardlink-changed":
				records[0].LinkGroup = "g"
				other := carrierFile(t, p, "other", "other")
				other.LinkGroup = "g"
				records = append(records, other)
			case "native-conflict":
				capture = func(context.Context, string, hostdata.XattrCaptureLimits) (map[string][]byte, error) {
					return map[string][]byte{"case": {9}}, nil
				}
			case "capture-error":
				capture = func(context.Context, string, hostdata.XattrCaptureLimits) (map[string][]byte, error) {
					return nil, fs.ErrPermission
				}
			case "keep-refused":
				opts.Keep = func(string, []byte) bool { return false }
			case "budget":
				opts.CaptureLimits = &hostdata.XattrCaptureLimits{}
			case "cancel":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				opts.Context = ctx
			case "missing-root":
				opts.MetadataRoot = filepath.Join(m, "missing")
			case "invalid-mode":
				mode := uint32(1 << 30)
				records[0].Darwin.Mode = &mode
			case "wrong-mode":
				mode := uint32(0040000)
				records[0].Darwin.Mode = &mode
			}
			commitCarrier(t, s, records)
			if _, _, e := walkCarrierUsing(p, opts, makeCarrierNode, capture); e == nil {
				t.Fatal("unexpected success")
			}
		})
	}
}
func TestCarrierWalkCompressionAndSidecar(t *testing.T) {
	p, m, s := carrierFixture(t)
	r := carrierFile(t, p, "file", "file")
	values := map[string][]byte{hostdata.DecmpfsName: compressionHeader(4), hostdata.ResourceForkName: {3, 4}}
	r.Attributes = attrsCarrier(t, s, values)
	data, e := appledouble.FromXattrs(values).Encode()
	if e != nil {
		t.Fatal(e)
	}
	ad, e := s.PutBlob(context.Background(), bytes.NewReader(data), int64(len(data)))
	if e != nil {
		t.Fatal(e)
	}
	r.AppleDouble = &ad
	flags := hostdata.UFCompressed
	r.Darwin.Flags = &flags
	commitCarrier(t, s, []metatransport.Record{r})
	opts := &Options{MetadataRoot: m, Compression: true, HardLinks: true, Keep: func(string, []byte) bool { return true }}
	got, _, e := walkCarrierUsing(p, opts, makeCarrierNode, emptyCapture)
	if e != nil || len(got.Children[0].Data) != 0 {
		t.Fatal(e)
	}
	opts.Compression = false
	warned := false
	opts.Warn = func(string, fidelity.Kind, string) { warned = true }
	got, report, e := walkCarrierUsing(p, opts, makeCarrierNode, emptyCapture)
	if e != nil || !warned || report.Count(fidelity.Compression) != 1 || string(got.Children[0].Data) != "payload" || *got.Children[0].BSDFlags != 0 {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(p, "file"), []byte("edited"), 0600)
	opts.Compression = true
	if _, _, e = walkCarrierUsing(p, opts, makeCarrierNode, emptyCapture); !errors.Is(e, metatransport.ErrConflict) {
		t.Fatal(e)
	}
}
func TestCarrierWalkUnsupportedNamespace(t *testing.T) {
	p, m, s := carrierFixture(t)
	r := carrierFile(t, p, "file", "file")
	r.Attributes = attrsCarrier(t, s, map[string][]byte{"empty": {}})
	commitCarrier(t, s, []metatransport.Record{r})
	capture := func(context.Context, string, hostdata.XattrCaptureLimits) (map[string][]byte, error) {
		return nil, hostdata.ErrXattrUnsupported
	}
	got, _, e := walkCarrierUsing(p, &Options{MetadataRoot: m}, makeCarrierNode, capture)
	if e != nil || got.Children[0].Xattrs["empty"] == nil {
		t.Fatal(e)
	}
}
func TestCarrierStateSpecialBits(t *testing.T) {
	n := Node{}
	mode := uint32(0107777)
	r := metatransport.Record{Kind: "file", Darwin: metatransport.DarwinState{Mode: &mode}}
	if e := applyCarrierState(&n, r); e != nil {
		t.Fatal(e)
	}
	if n.Mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != (os.ModeSetuid | os.ModeSetgid | os.ModeSticky) {
		t.Fatal(n.Mode)
	}
	mode = 0120777
	r.Kind = "symlink"
	if e := applyCarrierState(&n, r); e != nil {
		t.Fatal(e)
	}
}
func TestCarrierWalkMissingAndDamagedMetadata(t *testing.T) {
	p, m, _ := carrierFixture(t)
	if _, _, e := walkCarrierUsing(p, &Options{MetadataRoot: m}, makeCarrierNode, emptyCapture); !errors.Is(e, fs.ErrNotExist) {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(m, "manifest.json"), []byte("broken"), 0600)
	if _, _, e := Walk(p, &Options{MetadataRoot: m}, makeCarrierNode); e == nil {
		t.Fatal("corruption ignored")
	}
}

type faultCarrierTree struct {
	carrierTree
	stat       func(string) (os.FileInfo, error)
	readlink   func(string) (string, error)
	read       func(string) ([]byte, error)
	filesystem fs.FS
}

func (f faultCarrierTree) Lstat(n string) (os.FileInfo, error) {
	if f.stat != nil {
		return f.stat(n)
	}
	return f.carrierTree.Lstat(n)
}
func (f faultCarrierTree) Readlink(n string) (string, error) {
	if f.readlink != nil {
		return f.readlink(n)
	}
	return f.carrierTree.Readlink(n)
}
func (f faultCarrierTree) ReadFile(n string) ([]byte, error) {
	if f.read != nil {
		return f.read(n)
	}
	return f.carrierTree.ReadFile(n)
}
func (f faultCarrierTree) FS() fs.FS {
	if f.filesystem != nil {
		return f.filesystem
	}
	return f.carrierTree.FS()
}

type carrierModeInfo struct {
	os.FileInfo
	mode os.FileMode
}

func (i carrierModeInfo) Mode() os.FileMode { return i.mode }
func (i carrierModeInfo) IsDir() bool       { return i.mode.IsDir() }

type errorFS struct{ err error }

func (f errorFS) Open(string) (fs.File, error) { return nil, f.err }
func TestCarrierWalkControlledReads(t *testing.T) {
	for _, which := range []string{"open", "stat", "special", "read", "readdir", "link", "readlink-error", "cancel-child", "value-budget", "metadata-limits"} {
		t.Run(which, func(t *testing.T) {
			p, m, s := carrierFixture(t)
			r := carrierFile(t, p, "file", "file")
			commitCarrier(t, s, []metatransport.Record{r})
			opts := &Options{MetadataRoot: m}
			capture := emptyCapture
			sentinel := errors.New("injected")
			if which == "value-budget" {
				opts.CaptureLimits = &hostdata.XattrCaptureLimits{NameBytes: 10, ValueBytes: 0, TotalBytes: 10}
				capture = func(context.Context, string, hostdata.XattrCaptureLimits) (map[string][]byte, error) {
					return map[string][]byte{"value": {1}}, nil
				}
			}
			if which == "metadata-limits" {
				limits := metatransport.DefaultLimits()
				limits.ManifestBytes = 0
				opts.MetadataLimits = &limits
			}
			if which == "cancel-child" {
				ctx, cancel := context.WithCancel(context.Background())
				opts.Context = ctx
				capture = func(context.Context, string, hostdata.XattrCaptureLimits) (map[string][]byte, error) {
					cancel()
					return nil, nil
				}
			}
			open := func(p string) (carrierTree, error) {
				if which == "open" {
					return nil, sentinel
				}
				root, e := os.OpenRoot(p)
				if e != nil {
					return nil, e
				}
				f := faultCarrierTree{carrierTree: root}
				switch which {
				case "stat":
					f.stat = func(string) (os.FileInfo, error) { return nil, sentinel }
				case "special":
					f.stat = func(n string) (os.FileInfo, error) {
						i, e := root.Lstat(n)
						return carrierModeInfo{i, os.ModeNamedPipe}, e
					}
				case "read":
					f.read = func(string) ([]byte, error) { return nil, sentinel }
				case "readdir":
					f.filesystem = errorFS{sentinel}
				case "link", "readlink-error":
					f.stat = func(n string) (os.FileInfo, error) {
						i, e := root.Lstat(n)
						if n == "unrecorded" {
							return carrierModeInfo{i, os.ModeSymlink}, e
						}
						return i, e
					}
					f.readlink = func(string) (string, error) {
						if which == "readlink-error" {
							return "", sentinel
						}
						return "target", nil
					}
				}
				return f, nil
			}
			if which == "link" || which == "readlink-error" {
				os.WriteFile(filepath.Join(p, "unrecorded"), nil, 0600)
			}
			got, _, e := walkCarrierBound(p, opts, makeCarrierNode, capture, open)
			if which == "link" {
				if e != nil {
					t.Fatal(e)
				}
				if string(got.Children[1].Data) != "target" {
					t.Fatal(got)
				}
			} else if e == nil {
				t.Fatal("unexpected success")
			}
		})
	}
}
func TestCarrierWalkRetainsOrdinaryEdits(t *testing.T) {
	p, m, s := carrierFixture(t)
	r := carrierFile(t, p, "file", "file")
	commitCarrier(t, s, []metatransport.Record{r})
	os.WriteFile(filepath.Join(p, "file"), []byte("user edit"), 0600)
	got, _, e := walkCarrierUsing(p, &Options{MetadataRoot: m}, makeCarrierNode, emptyCapture)
	if e != nil || string(got.Children[0].Data) != "user edit" {
		t.Fatal(e)
	}
}

func TestCarrierWalkNativeBaseline(t *testing.T) {
	for _, which := range []string{"unchanged", "new", "changed", "deleted", "unsupported", "budget"} {
		t.Run(which, func(t *testing.T) {
			p, m, s := carrierFixture(t)
			r := carrierFile(t, p, "file", "file")
			r.Attributes = attrsCarrier(t, s, map[string][]byte{"logical": {2}})
			r.NativeCaptured = true
			r.NativeAttributes = attrsCarrier(t, s, map[string][]byte{"automatic": {1}, "logical": {2}})
			if which == "unsupported" {
				r.NativeCaptured = false
				r.NativeUnsupported = true
				r.NativeAttributes = nil
			}
			commitCarrier(t, s, []metatransport.Record{r})
			capture := func(_ context.Context, name string, _ hostdata.XattrCaptureLimits) (map[string][]byte, error) {
				if filepath.Base(name) != "file" {
					return nil, nil
				}
				native := map[string][]byte{"automatic": {1}, "logical": {2}}
				switch which {
				case "new":
					native["new"] = []byte{3}
				case "changed":
					native["logical"] = []byte{3}
				case "deleted":
					delete(native, "logical")
				case "unsupported":
					return nil, hostdata.ErrXattrUnsupported
				}
				return native, nil
			}
			opts := &Options{MetadataRoot: m}
			if which == "budget" {
				opts.CaptureLimits = &hostdata.XattrCaptureLimits{NameBytes: 10, ValueBytes: 10, TotalBytes: 1}
			}
			got, _, e := walkCarrierUsing(p, opts, makeCarrierNode, capture)
			if which == "changed" || which == "deleted" || which == "budget" {
				if e == nil {
					t.Fatal("expected conflict/budget")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			attrs := got.Children[0].Xattrs
			if attrs["automatic"] != nil || !bytes.Equal(attrs["logical"], []byte{2}) {
				t.Fatal(attrs)
			}
			if which == "new" && !bytes.Equal(attrs["new"], []byte{3}) {
				t.Fatal(attrs)
			}
		})
	}
}

func TestCarrierRejectsPartialIndependentTimes(t *testing.T) {
	stamp := time.Unix(123, 0)
	for _, state := range []metatransport.DarwinState{{Birth: &stamp}, {Change: &stamp}, {Access: &stamp}, {Birth: &stamp, Modify: &stamp, Access: &stamp}} {
		if e := applyCarrierState(&Node{}, metatransport.Record{Kind: "file", Darwin: state}); !errors.Is(e, metatransport.ErrInvalid) {
			t.Fatal(e)
		}
	}
	n := Node{}
	if e := applyCarrierState(&n, metatransport.Record{Kind: "file", Darwin: metatransport.DarwinState{Modify: &stamp}}); e != nil || n.ModTime != stamp || n.Times != nil {
		t.Fatal(e)
	}
}
