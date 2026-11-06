package hfsplus

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

type rootWriteProbe struct{ calls int }

func (w *rootWriteProbe) WriteAt(p []byte, _ int64) (int, error) { w.calls++; return len(p), nil }

func TestHFSValuesRootSources(t *testing.T) {
	for _, root := range []*Entry{
		{Mode: os.ModeSymlink}, {Mode: os.ModeNamedPipe},
		{Data: []byte{}}, {Data: []byte("lost")}, {DataValue: bytes.NewReader(nil)},
		{Open: func() (io.ReadCloser, error) { t.Fatal("root source opened"); return nil, nil }},
		{Size: 1}, {ResourceFork: []byte{}}, {ResourceForkValue: bytes.NewReader(nil)},
		{Xattrs: map[string][]byte{decmpfs.AttributeName: {}}},
		{XattrValues: map[string]appledouble.Value{decmpfs.AttributeName: bytes.NewReader(nil)}},
	} {
		w := &rootWriteProbe{}
		if err := CreateImage(w, 0, "root", root, nil); err == nil {
			t.Fatalf("root source ignored: %#v", root)
		}
		if w.calls != 0 {
			t.Fatal("output written before root rejection")
		}
	}
	for _, mode := range []os.FileMode{0, 0755, os.ModeDir, os.ModeDir | 0700} {
		if err := validateRootSources(&Entry{Mode: mode}); err != nil {
			t.Fatalf("directory root: %v", err)
		}
	}
}
