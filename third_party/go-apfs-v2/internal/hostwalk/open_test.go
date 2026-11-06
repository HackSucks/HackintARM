package hostwalk

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

func valueBytes(t *testing.T, v appledouble.Value) []byte {
	t.Helper()
	p := make([]byte, v.Size())
	n, err := v.ReadAt(p, 0)
	if n != len(p) || err != nil {
		t.Fatalf("read %d %v", n, err)
	}
	return p
}
func TestOpenWalkBorrowedLifetime(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "sub", "data")
	content := bytes.Repeat([]byte("abc"), 100000)
	if err := os.WriteFile(file, content, 0600); err != nil {
		t.Fatal(err)
	}
	tree, err := OpenWalk(dir, nil, makeCarrierNode)
	if err != nil {
		t.Fatal(err)
	}
	defer tree.Close()
	node := tree.Root.Children[0].Children[0]
	if node.Data != nil || node.DataValue == nil || tree.Report == nil {
		t.Fatal("not borrowed")
	}
	v := node.DataValue
	if !bytes.Equal(valueBytes(t, v), content) {
		t.Fatal("content")
	}
	p := make([]byte, 4)
	if n, e := v.ReadAt(p, -1); n != 0 || !errors.Is(e, fs.ErrInvalid) {
		t.Fatal(n, e)
	}
	if n, e := v.ReadAt(nil, v.Size()+1); n != 0 || e != nil {
		t.Fatal(n, e)
	}
	if n, e := v.ReadAt(p, v.Size()-2); n != 2 || !errors.Is(e, io.EOF) {
		t.Fatal(n, e)
	}
	if err = tree.Close(); err != nil {
		t.Fatal(err)
	}
	if err = tree.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = v.ReadAt(p, 0); !errors.Is(err, fs.ErrClosed) {
		t.Fatal(err)
	}
}
func TestOpenWalkFailures(t *testing.T) {
	for _, test := range []string{"missing", "cancel", "read-cancel", "removed", "resized", "replaced", "directory", "root-closed", "walk-error"} {
		t.Run(test, func(t *testing.T) {
			dir := t.TempDir()
			file := filepath.Join(dir, "file")
			os.WriteFile(file, []byte("abc"), 0600)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			opts := &Options{Context: ctx}
			switch test {
			case "missing":
				dir = filepath.Join(dir, "absent")
			case "cancel":
				cancel()
			case "walk-error":
				opts.MetadataRoot = filepath.Join(dir, "absent")
			}
			tree, err := OpenWalk(dir, opts, makeCarrierNode)
			if test == "missing" || test == "cancel" || test == "walk-error" {
				if err == nil {
					tree.Close()
					t.Fatal("accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer tree.Close()
			switch test {
			case "read-cancel":
				cancel()
			case "removed":
				os.Remove(file)
			case "resized":
				os.WriteFile(file, []byte("abcd"), 0600)
			case "replaced":
				os.Rename(file, file+".old")
				os.WriteFile(file, []byte("abc"), 0600)
			case "directory":
				os.Remove(file)
				os.Mkdir(file, 0700)
			case "root-closed":
				tree.owner.root.Close()
			}
			if _, err = tree.Root.Children[0].DataValue.ReadAt(make([]byte, 3), 0); err == nil {
				t.Fatal("read accepted mutation")
			}
		})
	}
}
func TestOpenWalkCarrierLargeAttributesAndEdits(t *testing.T) {
	p, m, s := carrierFixture(t)
	r := carrierFile(t, p, "mapped", "original")
	attr := bytes.Repeat([]byte{3}, 1<<20)
	r.Attributes = attrsCarrier(t, s, map[string][]byte{"large": attr, hostdata.ResourceForkName: {1, 2, 3}})
	commitCarrier(t, s, []metatransport.Record{r})
	os.WriteFile(filepath.Join(p, "mapped"), []byte("edited body"), 0600)
	tree, e := OpenWalk(p, &Options{MetadataRoot: m, KeepName: func(string) bool { return true }}, makeCarrierNode)
	if e != nil {
		t.Fatal(e)
	}
	defer tree.Close()
	n := tree.Root.Children[0]
	if n.Name != "original" || n.Data != nil || n.Xattrs != nil {
		t.Fatal(n)
	}
	if !bytes.Equal(valueBytes(t, n.XattrValues["large"]), attr) {
		t.Fatal("attr")
	}
	if string(valueBytes(t, n.DataValue)) != "edited body" {
		t.Fatal("edit lost")
	}
	v := n.XattrValues["large"]
	tree.Close()
	if _, e = v.ReadAt(make([]byte, 1), 0); e == nil {
		t.Fatal("closed carrier readable")
	}
}
func TestLazyCarrierBranches(t *testing.T) {
	for _, name := range []string{"keep", "baseline", "native-conflict", "baseline-corrupt", "logical-corrupt", "compressed", "decompress", "alias", "alias-body", "alias-read"} {
		t.Run(name, func(t *testing.T) {
			p, m, s := carrierFixture(t)
			r := carrierFile(t, p, "file", "file")
			r.Attributes = attrsCarrier(t, s, map[string][]byte{"case": {1}})
			records := []metatransport.Record{r}
			capture := emptyCapture
			o := &Options{MetadataRoot: m, Compression: true, HardLinks: true}
			switch name {
			case "keep":
				o.KeepName = func(string) bool { return false }
			case "baseline", "baseline-corrupt":
				records[0].NativeCaptured = true
				records[0].NativeAttributes = attrsCarrier(t, s, map[string][]byte{"native": {9}})
			case "native-conflict":
				capture = func(context.Context, string, hostdata.XattrCaptureLimits) (map[string][]byte, error) {
					return map[string][]byte{"case": {2}}, nil
				}
			case "compressed", "decompress":
				records[0].Attributes = attrsCarrier(t, s, map[string][]byte{hostdata.DecmpfsName: compressionHeader(4), hostdata.ResourceForkName: {3}})
				o.Compression = name == "compressed"
			case "alias", "alias-body", "alias-read":
				records[0].LinkGroup = "shared"
				tm := time.Unix(100, 0)
				records[0].Darwin.Modify = &tm
				other := carrierFile(t, p, "second", "second")
				other.LinkGroup = "shared"
				other.Darwin = records[0].Darwin
				other.Attributes = records[0].Attributes
				records = append(records, other)
				if name == "alias-body" {
					os.WriteFile(filepath.Join(p, "second"), []byte("changed"), 0600)
				}
			}
			commitCarrier(t, s, records)
			if name == "logical-corrupt" {
				os.WriteFile(filepath.Join(m, "blob-"+r.Attributes[0].Value.SHA256), []byte{2}, 0600)
			}
			root, e := os.OpenRoot(p)
			if e != nil {
				t.Fatal(e)
			}
			owner := &treeOwner{root: root, ctx: context.Background(), closers: []io.Closer{root}}
			o.owner = owner
			defer owner.close()
			if name == "baseline-corrupt" {
				o.CaptureLimits = &hostdata.XattrCaptureLimits{}
			}
			if name == "alias-read" {
				capture = func(ctx context.Context, path string, l hostdata.XattrCaptureLimits) (map[string][]byte, error) {
					if filepath.Base(path) == "second" {
						os.Remove(filepath.Join(p, "file"))
					}
					return emptyCapture(ctx, path, l)
				}
			}
			out, _, e := walkCarrierUsing(p, o, makeCarrierNode, capture)
			// A borrowed baseline is independent of the native allocation budget.
			wantErr := name == "keep" || name == "native-conflict" || name == "alias-body" || name == "alias-read" || name == "logical-corrupt"
			if wantErr {
				if e == nil {
					t.Fatal("expected failure")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			n := out.Children[0]
			if name == "compressed" && n.DataValue != nil {
				t.Fatal("duplicated compressed data")
			}
			if name == "decompress" {
				if n.DataValue == nil || len(n.XattrValues) != 0 {
					t.Fatal("decompress values")
				}
			}
			if name == "alias" && n.LinkGroup != out.Children[1].LinkGroup {
				t.Fatal("alias")
			}
		})
	}
}

type equalFaultValue struct {
	size int64
	n    int
	err  error
}

func (v equalFaultValue) Size() int64                           { return v.size }
func (v equalFaultValue) ReadAt(p []byte, _ int64) (int, error) { return min(v.n, len(p)), v.err }
func TestNodeAndValueEquality(t *testing.T) {
	good := bytes.NewReader([]byte{1})
	for _, tc := range []struct {
		a, b  appledouble.Value
		equal bool
		err   bool
	}{
		{good, bytes.NewReader([]byte{1}), true, false},
		{good, bytes.NewReader(nil), false, false},
		{good, bytes.NewReader([]byte{2}), false, false},
		{equalFaultValue{1, 0, io.EOF}, good, false, true},
		{equalFaultValue{1, 1, fs.ErrPermission}, good, false, true},
		{good, equalFaultValue{1, 1, fs.ErrPermission}, false, true},
	} {
		equal, e := valuesEqual(tc.a, tc.b)
		if equal != tc.equal || (e != nil) != tc.err {
			t.Fatal(equal, e)
		}
	}
	cases := [][2]Node{
		{{Mode: 0600}, {Mode: 0700}},
		{{Xattrs: map[string][]byte{"a": {}}}, {XattrValues: map[string]appledouble.Value{"b": bytes.NewReader(nil)}}},
		{{Xattrs: map[string][]byte{"a": {1}}}, {XattrValues: map[string]appledouble.Value{"a": bytes.NewReader([]byte{2})}}},
		{{Data: []byte{1}}, {Data: []byte{2}}},
	}
	for _, pair := range cases {
		eq, e := nodesEqual(pair[0], pair[1])
		if eq || e != nil {
			t.Fatal(eq, e)
		}
	}
	eq, e := nodesEqual(Node{Xattrs: map[string][]byte{"a": {1}}}, Node{XattrValues: map[string]appledouble.Value{"a": good}})
	if !eq || e != nil {
		t.Fatal(eq, e)
	}
	o := &treeOwner{}
	info := fakeLazyInfo{}
	if _, e = o.borrow(".", info); !errors.Is(e, fs.ErrInvalid) {
		t.Fatal(e)
	}
}

type fakeLazyInfo struct{}

func (fakeLazyInfo) Name() string       { return "dir" }
func (fakeLazyInfo) Size() int64        { return 0 }
func (fakeLazyInfo) Mode() os.FileMode  { return os.ModeDir }
func (fakeLazyInfo) ModTime() time.Time { return time.Time{} }
func (fakeLazyInfo) IsDir() bool        { return true }
func (fakeLazyInfo) Sys() any           { return nil }

func compressionHeader(method uint32) []byte {
	p := make([]byte, 16)
	copy(p, "fpmc")
	binary.LittleEndian.PutUint32(p[4:], method)
	return p
}

func TestCarrierDecompressRetainsIndependentFork(t *testing.T) {
	for _, lazy := range []bool{false, true} {
		for _, method := range []uint32{3, 4, 5} {
			t.Run(fmt.Sprintf("%t/%d", lazy, method), func(t *testing.T) {
				p, m, s := carrierFixture(t)
				r := carrierFile(t, p, "file", "file")
				r.Attributes = attrsCarrier(t, s, map[string][]byte{hostdata.DecmpfsName: append(compressionHeader(method), 0xff), hostdata.ResourceForkName: []byte("fork"), "other": {9}})
				commitCarrier(t, s, []metatransport.Record{r})
				opts := &Options{MetadataRoot: m}
				if lazy {
					root, err := os.OpenRoot(p)
					if err != nil {
						t.Fatal(err)
					}
					opts.owner = &treeOwner{root: root, ctx: context.Background(), closers: []io.Closer{root}}
					defer opts.owner.close()
				}
				got, _, err := walkCarrierUsing(p, opts, makeCarrierNode, emptyCapture)
				if method == 5 {
					if err == nil {
						t.Fatal("unknown compression shape accepted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				attrs := nodeValues(got.Children[0].Node)
				_, present := attrs[hostdata.ResourceForkName]
				if present != (method == 3) {
					t.Fatal("independent fork lost", attrs)
				}
				if _, present = attrs["other"]; !present {
					t.Fatal("unrelated attribute lost")
				}
			})
		}
	}
}
