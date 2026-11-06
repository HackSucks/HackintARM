package hostdata

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
)

func TestEntryTypeFixtureProvenance(t *testing.T) {
	var corpus struct {
		Schema          int
		MacOS, Compiler string
		Hashes          map[string]string `json:"source_sha256"`
		Cases           map[string]struct {
			Errno, Size int
			Vnode       int `json:"vnode_type"`
			StatErrno   int `json:"stat_errno"`
		}
	}
	data, err := os.ReadFile("../../testdata/appledouble/native/entry-type.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	referenceSources, referenceErr := captureprovenance.Reference(os.DirFS("../.."), corpus.Hashes)
	if referenceErr != nil {
		t.Fatal(referenceErr)
	}
	harness, err := captureprovenance.Inventory(referenceSources)
	if err != nil {
		t.Fatal(err)
	}
	if err = captureprovenance.Verify(referenceSources, corpus.Hashes); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != 1 || corpus.MacOS == "" || corpus.Compiler == "" || len(corpus.Hashes) != 3+len(harness) || len(corpus.Cases) != 17 {
		t.Fatal("incomplete native record")
	}
	for _, p := range []string{"scripts/capture-entry-type.go", "testdata/appledouble/native/entry-type.c", "internal/testutil/entrytype/fixture_darwin.go"} {
		b, err := captureprovenance.ReadSource(referenceSources, corpus.Hashes, p)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(b)
		if corpus.Hashes[p] != hex.EncodeToString(h[:]) {
			t.Fatal("stale native record", p)
		}
	}
	for _, name := range []string{"ordinary", "read", "readsecurity", "readextattr", "write", "writeattr", "writesecurity", "writeextattr", "read+readsecurity+readextattr"} {
		got, ok := corpus.Cases[name]
		if !ok || got.Errno != 0 || got.Vnode != 1 || got.Size != 8 {
			t.Fatal("wrong basic attribute result", name, got)
		}
		want := 0
		if name == "readsecurity" || name == "read+readsecurity+readextattr" {
			want = 13
		}
		if got.StatErrno != want {
			t.Fatal("lost ACL distinction", name, got)
		}
	}
	for _, name := range []string{"readattr", "readattr+readsecurity", "missing"} {
		got, ok := corpus.Cases[name]
		want := 13
		if name == "missing" {
			want = 2
		}
		if !ok || got.Errno != want || got.StatErrno != want || got.Size != 0 || got.Vnode != 0 {
			t.Fatal("wrong failure", name, got)
		}
	}
	for name, want := range map[string]int{"directory": 2, "symlink": 5, "dangling": 5, "fifo": 7, "socket": 6} {
		got, ok := corpus.Cases[name]
		if !ok || got.Errno != 0 || got.StatErrno != 0 || got.Vnode != want || got.Size != 8 {
			t.Fatal("wrong native type", name, got)
		}
	}
}
