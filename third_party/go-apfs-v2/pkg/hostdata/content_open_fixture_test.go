package hostdata

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
)

func TestContentOpenFixtureProvenance(t *testing.T) {
	base := filepath.Join("..", "..")
	data, err := os.ReadFile(filepath.Join(base, "testdata/appledouble/native/content-open.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Schema   int               `json:"schema"`
		MacOS    string            `json:"macos"`
		Compiler string            `json:"compiler"`
		Hashes   map[string]string `json:"source_sha256"`
		Cases    map[string]struct {
			Errno     int    `json:"errno"`
			WrongType bool   `json:"wrong_type"`
			Hex       string `json:"hex"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	referenceSources, referenceErr := captureprovenance.Reference(os.DirFS(base), fixture.Hashes)
	if referenceErr != nil {
		t.Fatal(referenceErr)
	}
	harness, err := captureprovenance.Inventory(referenceSources)
	if err != nil {
		t.Fatal(err)
	}
	if err = captureprovenance.Verify(referenceSources, fixture.Hashes); err != nil {
		t.Fatal(err)
	}
	if fixture.Schema != 1 || fixture.MacOS == "" || fixture.Compiler == "" || len(fixture.Cases) != 12 || len(fixture.Hashes) != 2+len(harness) {
		t.Fatal("incomplete native fixture")
	}
	for _, name := range []string{"scripts/capture-content-open.go", "testdata/appledouble/native/content-open.c"} {
		source, err := captureprovenance.ReadSource(referenceSources, fixture.Hashes, name)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(source)
		if fixture.Hashes[name] != hex.EncodeToString(digest[:]) {
			t.Fatal("stale native fixture", name)
		}
	}
	for _, name := range []string{"ordinary", "readattr", "readsecurity", "readextattr", "write", "writesecurity", "writeextattr"} {
		got, ok := fixture.Cases[name]
		if !ok || got.Errno != 0 || got.WrongType || got.Hex != hex.EncodeToString([]byte("unchanged")) {
			t.Fatal("invalid content success", name, got)
		}
	}
	for name, errno := range map[string]int{"read": 13, "missing": 2, "symlink": 62} {
		got, ok := fixture.Cases[name]
		if !ok || got.Errno != errno || got.WrongType || got.Hex != "" {
			t.Fatal("invalid native failure", name, got)
		}
	}
	for _, name := range []string{"directory", "fifo"} {
		got, ok := fixture.Cases[name]
		if !ok || got.Errno != 0 || !got.WrongType || got.Hex != "" {
			t.Fatal("invalid type rejection", name, got)
		}
	}
}
