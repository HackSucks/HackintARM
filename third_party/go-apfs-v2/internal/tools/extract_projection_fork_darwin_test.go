package tools

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

type projectedForkVolume struct{ carrierVolume }

func (v projectedForkVolume) Xattrs(n string) (map[string][]byte, error) {
	if n == "file" {
		return v.attrs, nil
	}
	return nil, nil
}
func TestProjectionStreamedForkBaseline(t *testing.T) {
	content := bytes.Repeat([]byte{7}, (1<<20)+1)
	volume := projectedForkVolume{carrierVolume{MapFS: fstest.MapFS{"file": {Data: []byte("body")}}, attrs: map[string][]byte{hostdata.ResourceForkName: content}}}
	e := newCarrierExtractor(t, volume)
	e.ProjectNative = true
	e.Xattrs = true
	e.NativeCaptureLimits = &hostdata.XattrCaptureLimits{NameBytes: hostdata.MaxXattrListSize, ValueBytes: 16384, TotalBytes: 32768}
	if err := e.ExtractAll(); err != nil {
		t.Fatal(err)
	}
	store, err := metatransport.Open(e.Destination, e.MetadataRoot, metatransport.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	m, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range m.Records {
		for _, a := range r.NativeAttributes {
			if a.Name == hostdata.ResourceForkName {
				found = a.Value.Size == int64(len(content))
			}
		}
	}
	if !found {
		t.Fatal("large native baseline omitted")
	}
	opts := &apfswrite.WalkOptions{MetadataRoot: e.MetadataRoot, CaptureLimits: e.NativeCaptureLimits}
	tree, err := apfswrite.OpenEntryTreeFromDir(e.Destination, opts)
	if err != nil {
		t.Fatal(err)
	}
	fork := tree.Root.Children[0].XattrValues[hostdata.ResourceForkName]
	if fork == nil || fork.Size() != int64(len(content)) {
		t.Fatal("borrowed fork missing")
	}
	p := make([]byte, 3)
	if _, err = fork.ReadAt(p, 0); err != nil || !bytes.Equal(p, content[:3]) {
		t.Fatal(p, err)
	}
	tree.Close()
	file, err := os.Open(filepath.Join(e.Destination, "file"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	native, err := hostdata.OpenResourceFork(file, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = native.WriteAt([]byte{8}, 0); err != nil {
		t.Fatal(err)
	}
	native.Close()
	if tree, err = apfswrite.OpenEntryTreeFromDir(e.Destination, opts); !errors.Is(err, metatransport.ErrConflict) {
		if tree != nil {
			tree.Close()
		}
		t.Fatal("native edit was ignored", err)
	}
}

func TestCarrierNativeInitialForkBaseline(t *testing.T) {
	content := bytes.Repeat([]byte{5}, (1<<20)+1)
	e := newCarrierExtractor(t, carrierVolume{MapFS: fstest.MapFS{"file": {Data: []byte("body")}}})
	e.NativeCaptureLimits = &hostdata.XattrCaptureLimits{NameBytes: hostdata.MaxXattrListSize, ValueBytes: 16384, TotalBytes: 32768}
	ops := carrierExtractionOps{os.ReadDir, os.OpenRoot, func(ctx context.Context, root *os.Root, name string, limits hostdata.XattrCaptureLimits) (map[string]appledouble.Value, error) {
		if name == "file" {
			f, err := root.OpenFile(name, os.O_RDWR, 0)
			if err != nil {
				return nil, err
			}
			_, err = hostdata.ReplaceResourceFork(ctx, f, bytes.NewReader(content))
			err = errors.Join(err, f.Close())
			if err != nil {
				return nil, err
			}
		}
		return hostdata.CaptureXattrValuesAt(ctx, root, name, limits)
	}}
	if err := e.extractCarrierUsing(".", "", ops); err != nil {
		t.Fatal(err)
	}
	store, err := metatransport.Open(e.Destination, e.MetadataRoot, metatransport.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	manifest, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range manifest.Records {
		if r.Original != "file" {
			continue
		}
		values, err := store.BorrowAttributes(context.Background(), r.NativeAttributes)
		if err != nil {
			t.Fatal(err)
		}
		fork := values[hostdata.ResourceForkName]
		if !r.NativeCaptured || fork == nil || fork.Size() != int64(len(content)) {
			t.Fatal(r)
		}
		got := make([]byte, 17)
		if _, err := fork.ReadAt(got, fork.Size()-17); err != nil || !bytes.Equal(got, content[:17]) {
			t.Fatal(got, err)
		}
		return
	}
	t.Fatal("native fork baseline absent")
}
