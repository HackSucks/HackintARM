package hostdata

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

func TestCompressionLifecycleProvenance(t *testing.T) {
	testCompressionProvenance(t, "compression-lifecycle", 591, []string{"internal/testutil/diskimage/attachment.go", "internal/testutil/diskimage/detach.go"})
}
func TestCompressionOperationProvenance(t *testing.T) {
	for _, name := range []string{"compression-operation", "compression-operation-macos26", "compression-operation-macos15"} {
		t.Run(name, func(t *testing.T) {
			testCompressionProvenanceFrom(t, name, "compression-operation", 330, []string{"testdata/appledouble/native/compression-lifecycle-interpose.c", "scripts/capture-compression-operation_test.go", "pkg/osversion/version.go", "pkg/osversion/macos.go", "pkg/osversion/host.go", "pkg/osversion/host_darwin.go", "pkg/osversion/host_other.go"})
			heldSnapshots := 0
			for i, c := range compressionTrials(t, name, 330) {
				if c.Observation.AfterMode&0170000 == 0100000 && (c.Observation.ObserverHeldMetadataUnchanged == nil || !*c.Observation.ObserverHeldMetadataUnchanged) {
					t.Fatal("missing or changed held metadata snapshot", i)
				}
				if c.Observation.ObserverHeldMetadataUnchanged != nil && *c.Observation.ObserverHeldMetadataUnchanged {
					heldSnapshots++
				}
				if c.Filesystem == "" || c.Scenario == "" || c.Requested == "" || c.Inline == "" || c.Trace == "" {
					t.Fatal("incomplete typed native operation observation", i)
				}
			}
			if heldSnapshots != 306 {
				t.Fatal("incomplete held metadata inventory", heldSnapshots)
			}
		})
	}
}
func testCompressionProvenance(t *testing.T, name string, count int, additional []string) {
	t.Helper()
	testCompressionProvenanceFrom(t, name, name, count, additional)
}
func testCompressionProvenanceFrom(t *testing.T, fixture, name string, count int, additional []string) {
	t.Helper()
	file, e := os.Open("../../testdata/appledouble/native/" + fixture + ".json.gz")
	if e != nil {
		t.Fatal(e)
	}
	defer file.Close()
	z, e := gzip.NewReader(file)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var corpus struct {
		Schema                       int
		Host, Compiler, SDK, Library string
		Sources                      map[string]string
		Cases                        []json.RawMessage
	}
	if e = json.NewDecoder(z).Decode(&corpus); e != nil {
		t.Fatal(e)
	}
	if corpus.Schema != 1 || len(corpus.Cases) != count || corpus.Host == "" || corpus.SDK == "" || !strings.Contains(corpus.Compiler, "clang") || !strings.Contains(corpus.Library, "-uuid:") {
		t.Fatal("incomplete native lifecycle provenance")
	}
	if name == "compression-operation" {
		version, err := osversion.ParseProductVersion(corpus.Host)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := osversion.ProfileForMacOS(version)
		want := map[string]osversion.MacOSProfile{"compression-operation": osversion.MacOS27, "compression-operation-macos26": osversion.MacOS26, "compression-operation-macos15": osversion.MacOS15}[fixture]
		if err != nil || want == 0 || actual != want {
			t.Fatal("native operation profile mismatch", fixture, version, err)
		}
	}
	referenceSources, referenceErr := captureprovenance.Reference(os.DirFS("../.."), corpus.Sources)
	if referenceErr != nil {
		t.Fatal(referenceErr)
	}
	if err := captureprovenance.Verify(referenceSources, corpus.Sources); err != nil {
		t.Fatal(err)
	}
	for _, path := range append(additional, "scripts/capture-"+name+".go", "testdata/appledouble/native/"+name+".c", "testdata/appledouble/native/"+name+"-interpose.c", "testdata/appledouble/native/compression-policy.c", "go.mod", "go.sum") {
		data, e := captureprovenance.ReadSource(referenceSources, corpus.Sources, path)
		if e != nil {
			t.Fatal(e)
		}
		if fmt.Sprintf("%x", sha256.Sum256(data)) != corpus.Sources[path] {
			t.Fatal("stale native lifecycle source", path)
		}
	}
	for _, key := range []string{"arm64-" + name + ".c.ast.json", "x86_64-" + name + ".c.ast.json", "arm64-" + name + "-interpose.c.ast.json", "x86_64-" + name + "-interpose.c.ast.json", "AppleFSCompression.disassembly.txt"} {
		if len(corpus.Sources[key]) != 64 {
			t.Fatal("missing AST/disassembly evidence", key)
		}
	}
	for _, header := range []string{"sys/mount.h", "sys/stat.h", "sys/xattr.h", "sys/attr.h", "sys/time.h"} {
		found := false
		for path, hash := range corpus.Sources {
			if strings.HasSuffix(path, "/usr/include/"+header) && len(hash) == 64 {
				found = true
			}
		}
		if !found {
			t.Fatal("missing native SDK header", header)
		}
	}
}
