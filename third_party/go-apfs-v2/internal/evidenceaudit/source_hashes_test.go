package evidenceaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"testing/fstest"
)

func TestSourceHashesPortableInventory(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "pkg", "hostdata", "accesstime"), 0700); err != nil {
		t.Fatal(err)
	}
	contents := map[string][]byte{"pkg/hostdata/accesstime/access_time_windows.go": []byte("package hostdata\r\n"), "pkg/hostdata/accesstime/access_time_darwin.go": []byte("package hostdata\n"), "go.mod": []byte("module example\n")}
	want := map[string]string{}
	for name, data := range contents {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), data, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		want[name] = hex.EncodeToString(sum[:])
	}
	got, err := SourceHashes(os.DirFS(root), []string{"go.mod", "pkg/hostdata/accesstime/*.go", "go.mod"})
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal(got, want, err)
	}
	if got["pkg/hostdata/accesstime/access_time_windows.go"] == got["pkg/hostdata/accesstime/access_time_darwin.go"] {
		t.Fatal("source bytes were normalized")
	}
	// The actual Windows OS filesystem is used above when this test runs on CI;
	// it must produce the same io/fs inventory as this portable reference.
	reference := fstest.MapFS{}
	for name, data := range contents {
		reference[name] = &fstest.MapFile{Data: data}
	}
	other, err := SourceHashes(reference, []string{"go.mod", "pkg/hostdata/accesstime/*.go"})
	if err != nil || !reflect.DeepEqual(other, got) {
		t.Fatal(other, got, err)
	}
}

func TestSourceHashesRejectsIncompleteInventory(t *testing.T) {
	source := fstest.MapFS{"directory": &fstest.MapFile{Mode: fs.ModeDir | 0700}, "present": &fstest.MapFile{Data: []byte("exact")}}
	for _, patterns := range [][]string{{"["}, {"missing"}, {"directory"}, {"present", "missing"}} {
		if got, err := SourceHashes(source, patterns); err == nil || got != nil {
			t.Fatal(patterns, got, err)
		}
	}
	if _, err := SourceHashes(source, []string{"missing"}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
}
