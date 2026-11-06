package hostdata

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

// Retain the unresolved native allocation counterexample independently of the
// accepted operation profiles. This test does not normalize the native checker
// or allow these counts as interchangeable results in operation acceptance.
func TestCompressionAllocationObservations(t *testing.T) {
	type trial struct {
		Filesystem, Scenario, Requested, Inline string
		Attribute, Fork, Data                   []byte
		Observation                             struct {
			Storage struct{ Blocks int64 }
		}
	}
	type capture struct {
		Schema  int
		Host    string
		Sources map[string]string
		Cases   []trial
	}
	var observations [2]capture
	for i, name := range []string{"first", "second"} {
		f, err := os.Open("../../testdata/appledouble/native/allocation-observations/macos27-" + name + ".json.gz")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		z, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		defer z.Close()
		if err = json.NewDecoder(z).Decode(&observations[i]); err != nil {
			t.Fatal(err)
		}
		c := observations[i]
		if c.Schema != 1 || len(c.Cases) != 330 || c.Host == "" {
			t.Fatal("incomplete native allocation observation")
		}
		referenceSources, referenceErr := captureprovenance.Reference(os.DirFS("../.."), c.Sources)
		if referenceErr != nil {
			t.Fatal(referenceErr)
		}
		if err = captureprovenance.Verify(referenceSources, c.Sources); err != nil {
			t.Fatal(err)
		}
		version, err := osversion.ParseProductVersion(c.Host)
		if err != nil || version.Major != 27 {
			t.Fatal("unqualified allocation producer", version, err)
		}
		for _, path := range []string{"scripts/capture-compression-operation.go", "scripts/capture-compression-operation_test.go", "testdata/appledouble/native/compression-operation.c", "testdata/appledouble/native/compression-operation-interpose.c", "testdata/appledouble/native/compression-lifecycle-interpose.c", "testdata/appledouble/native/compression-policy.c", "pkg/osversion/version.go", "pkg/osversion/macos.go", "pkg/osversion/host.go", "pkg/osversion/host_darwin.go", "pkg/osversion/host_other.go", "go.mod", "go.sum"} {
			source := "../../" + path
			// These immutable counterexamples were captured before the toolchain
			// update. Verify their original module inputs against their recorded
			// hashes. Fresh qualification records its own current module provenance.
			if path == "go.mod" || path == "go.sum" {
				source = "../../testdata/appledouble/native/allocation-observations/capture-" + path + ".txt"
			}
			data, err := captureprovenance.ReadSource(referenceSources, c.Sources, path)
			if path == "go.mod" || path == "go.sum" {
				originalModule, moduleErr := os.ReadFile(source)
				if moduleErr != nil || fmt.Sprintf("%x", sha256.Sum256(originalModule)) != c.Sources[path] {
					t.Fatal("original allocation module bytes", path, moduleErr)
				}
			}

			if err != nil {
				t.Fatal(err)
			}
			if fmt.Sprintf("%x", sha256.Sum256(data)) != c.Sources[path] {
				t.Fatal("stale allocation oracle source", path)
			}
		}
	}
	if observations[0].Host != observations[1].Host {
		t.Fatal("different native producer")
	}
	for _, example := range []struct {
		index         int
		inline        string
		first, second int64
	}{{100, "default", 368, 264}, {101, "no", 352, 384}} {
		a, b := observations[0].Cases[example.index], observations[1].Cases[example.index]
		for _, c := range []trial{a, b} {
			if c.Filesystem != "host" || c.Scenario != "multi-block" || c.Requested != "9" || c.Inline != example.inline {
				t.Fatal("wrong native operation identity")
			}
		}
		if len(a.Data) != 131076 || len(a.Attribute) == 0 || len(a.Fork) == 0 || !bytes.Equal(a.Data, b.Data) || !bytes.Equal(a.Attribute, b.Attribute) || !bytes.Equal(a.Fork, b.Fork) {
			t.Fatal("counterexample no longer has identical stored and logical bytes")
		}
		if a.Observation.Storage.Blocks != example.first || b.Observation.Storage.Blocks != example.second {
			t.Fatal("changed recorded physical allocation")
		}
	}
}
