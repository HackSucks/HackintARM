package apfswrite_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestStreamedValuesProduceIdenticalImages(t *testing.T) {
	for _, size := range []int{0, 1, 3804, 3805, 5 << 20} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			data := bytes.Repeat([]byte{4}, size)
			fork := bytes.Repeat([]byte{7}, size)
			attrs := map[string][]byte{"empty": {}, "small": {1}, "large": data, "com.apple.ResourceFork": fork}
			makeRoot := func(lazy bool) *apfswrite.Entry {
				file := &apfswrite.Entry{Name: "file", Data: data, Xattrs: attrs}
				root := &apfswrite.Entry{Mode: os.ModeDir, Children: []*apfswrite.Entry{file}, Xattrs: map[string][]byte{"root": data}}
				if lazy {
					file.Data = nil
					file.DataValue = bytes.NewReader(data)
					file.Xattrs = nil
					file.XattrValues = map[string]appledouble.Value{}
					for name, b := range attrs {
						file.XattrValues[name] = bytes.NewReader(b)
					}
					root.Xattrs = nil
					root.XattrValues = map[string]appledouble.Value{"root": bytes.NewReader(data)}
				}
				return root
			}
			oldImage, newImage := &memImage{}, &memImage{}
			for _, tc := range []struct {
				img  *memImage
				lazy bool
			}{{oldImage, false}, {newImage, true}} {
				if err := apfswrite.CreateContainer(tc.img, 32<<20, &apfswrite.CreateOptions{Root: makeRoot(tc.lazy)}); err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(oldImage.data, newImage.data) {
				t.Fatal("streamed image differs")
			}
			volume := openVolumeMem(t, newImage)
			values, err := volume.XattrValues("file")
			if err != nil {
				t.Fatal(err)
			}
			for name, want := range attrs {
				value := values[name]
				if value == nil || value.Size() != int64(len(want)) {
					t.Fatal(name)
				}
				got, err := io.ReadAll(io.NewSectionReader(value, 0, value.Size()))
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal(name, err)
				}
			}
			if _, err = volume.XattrValues("missing"); err == nil {
				t.Fatal("missing attribute owner")
			}
			if _, err = volume.XattrValues("../bad"); err == nil {
				t.Fatal("invalid owner path")
			}
		})
	}
}

func TestOpenEntryTreeValues(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file"), []byte("content"), 0600); err != nil {
		t.Fatal(err)
	}
	old, _, err := apfswrite.EntryTreeFromDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := apfswrite.OpenEntryTreeFromDir(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tree.Close()
	if tree.Report == nil || tree.Root.Children[0].DataValue == nil || tree.Root.Children[0].Data != nil {
		t.Fatal("not borrowed")
	}
	images := []*memImage{{}, {}}
	for i, root := range []*apfswrite.Entry{old, tree.Root} {
		if err = apfswrite.CreateContainer(images[i], 32<<20, &apfswrite.CreateOptions{Root: root}); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(images[0].data, images[1].data) {
		t.Fatal("lazy walk changed image")
	}
	if err = tree.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = tree.Root.Children[0].DataValue.ReadAt(make([]byte, 1), 0); !errors.Is(err, fs.ErrClosed) {
		t.Fatal(err)
	}
	if _, err = apfswrite.OpenEntryTreeFromDir(filepath.Join(dir, "missing"), nil); err == nil {
		t.Fatal("missing tree accepted")
	}
}
