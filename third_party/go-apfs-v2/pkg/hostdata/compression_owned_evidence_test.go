package hostdata

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
)

func TestCompressionOwnedNativeEvidence(t *testing.T) {
	paths := []string{"../../testdata/appledouble/native/compression-owned-macos15.json.gz", "../../testdata/appledouble/native/compression-owned-macos26.json.gz", "../../testdata/appledouble/native/compression-owned-macos27.json.gz"}
	if extra := os.Getenv("APFS_COMPRESSION_OWNED_EVIDENCE"); extra != "" {
		paths = append(paths, extra)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			z, err := gzip.NewReader(f)
			if err != nil {
				t.Fatal(err)
			}
			defer z.Close()
			// JSON checkpoint names are snake_case in the independent C output.
			var raw struct {
				Schema              int
				Host, Compiler, SDK string
				Sources             map[string]string
				Cases               []struct {
					Filesystem  string
					Observation map[string]json.RawMessage
				}
			}
			if err = json.NewDecoder(z).Decode(&raw); err != nil {
				t.Fatal(err)
			}
			referenceSources, referenceErr := captureprovenance.Reference(os.DirFS("../.."), raw.Sources)
			if referenceErr != nil {
				t.Fatal(referenceErr)
			}
			harness, err := captureprovenance.Inventory(referenceSources)
			if err != nil {
				t.Fatal(err)
			}
			if err = captureprovenance.Verify(referenceSources, raw.Sources); err != nil {
				t.Fatal(err)
			}
			if raw.Schema != 1 || raw.Host == "" || raw.Compiler == "" || raw.SDK == "" || len(raw.Cases) != 72 || len(raw.Sources) != 15+len(harness) {
				t.Fatal("incomplete provenance", len(raw.Cases), len(raw.Sources))
			}
			for _, name := range []string{"testdata/appledouble/native/compression-owned.c", "scripts/capture-compression-owned.go", "pkg/osversion/version.go", "pkg/osversion/macos.go", "go.mod", "go.sum"} {
				b, e := captureprovenance.ReadSource(referenceSources, raw.Sources, name)
				if e != nil {
					t.Fatal(e)
				}
				sum := sha256.Sum256(b)
				if raw.Sources[name] != hex.EncodeToString(sum[:]) {
					t.Fatal("stale native source", name)
				}
			}
			for _, arch := range []string{"arm64", "x86_64"} {
				if len(raw.Sources[arch+"-compression-owned.ast.json"]) != 64 {
					t.Fatal("missing AST", arch)
				}
			}
			if len(raw.Sources["native-binary"]) != 64 {
				t.Fatal("missing native binary provenance")
			}
			seen := map[string]bool{}
			plain := make([]byte, 32768)
			for i := range plain {
				plain[i] = byte('A' + i%23)
			}
			for _, trial := range raw.Cases {
				get := func(key string, target any) {
					t.Helper()
					if e := decodeOwnedEvidence(trial.Observation[key], target); e != nil {
						t.Fatal(key, e)
					}
				}
				var route, mutation, data string
				var compressed, errno int
				get("route", &route)
				get("mutation", &mutation)
				get("compressed", &compressed)
				get("open_errno", &errno)
				key := trial.Filesystem + "/" + route + "/" + mutation + "/" + string(rune('0'+compressed))
				if seen[key] {
					t.Fatal("duplicate case", key)
				}
				seen[key] = true
				if compressed < 0 || compressed > 2 || route != "direct" && route != "root" || !strings.Contains("|none|root-before|root-after|leaf-after|", "|"+mutation+"|") {
					t.Fatal("unknown case", key)
				}
				var before, after, closed map[string]any
				get("before", &before)
				get("after_open", &after)
				get("after_close", &closed)
				for _, snapshot := range []map[string]any{before, after, closed} {
					if snapshot["inode"] != before["inode"] || snapshot["dev"] != before["dev"] || snapshot["size"] != json.Number("32768") || snapshot["links"] != json.Number("1") || snapshot["mode"] != json.Number("33188") || snapshot["filesystem"] != before["filesystem"] || snapshot["mount_flags"] != before["mount_flags"] {
						t.Fatal("held identity/volume changed", key)
					}
				}
				if trial.Filesystem == "APFS" && before["filesystem"] != "apfs" || trial.Filesystem == "HFS+" && before["filesystem"] != "hfs" {
					t.Fatal("wrong mounted filesystem", key)
				}
				if route == "direct" && mutation == "root-before" {
					if errno != 2 || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(before, closed) {
						t.Fatal("failed pathname mutated held source", key)
					}
					continue
				}
				if errno != 0 {
					t.Fatal("unexpected native acquisition", key, errno)
				}
				get("data", &data)
				decoded, e := hex.DecodeString(data)
				if e != nil || !bytes.Equal(decoded, plain) {
					t.Fatal("full native data differs", key, e)
				}
				if after["flags"] != json.Number("0") || closed["flags"] != json.Number("0") {
					t.Fatal("write-open state differs", key)
				}
				if compressed == 1 && after["attribute"] != nil {
					t.Fatal("active storage survived write-open", key)
				}
				if compressed != 1 && after["attribute"] != before["attribute"] {
					t.Fatal("uncompressed metadata changed", key)
				}
				var duplicate, zero map[string]any
				get("after_duplicate", &duplicate)
				get("after_zero_write", &zero)
				if !reflect.DeepEqual(duplicate, zero) {
					t.Fatal("zero-byte write changed metadata", key)
				}
			}
			if len(seen) != 72 {
				t.Fatal("case inventory", len(seen))
			}
		})
	}
}

// Native inode/device identities are integers, including values above float64's
// exact range. Distinct held files must never compare equal after decoding.
func TestCompressionOwnedNativeEvidenceExactIntegers(t *testing.T) {
	var snapshots []map[string]any
	if err := decodeOwnedEvidence([]byte(`[{"inode":9007199254740992,"dev":18446744073709551614},{"inode":9007199254740993,"dev":18446744073709551615}]`), &snapshots); err != nil {
		t.Fatal(err)
	}
	if snapshots[0]["inode"] == snapshots[1]["inode"] || snapshots[0]["dev"] == snapshots[1]["dev"] {
		t.Fatal("distinct native identities collapsed")
	}
	if snapshots[1]["inode"] != json.Number("9007199254740993") || snapshots[1]["dev"] != json.Number("18446744073709551615") {
		t.Fatal("native integer identity lost precision")
	}
}

func decodeOwnedEvidence(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	return decoder.Decode(target)
}
