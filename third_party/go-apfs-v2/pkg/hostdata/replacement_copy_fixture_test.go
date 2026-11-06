package hostdata

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
)

// Replay independently captured Darwin outcomes on every supported host. This
// does not claim that NTFS or Linux xattrs are native Darwin resource forks.
func TestReplacementCopyNativeFixture(t *testing.T) {
	data, err := os.ReadFile("../../testdata/appledouble/native/replacement-copy.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Schema int               `json:"schema"`
		Hashes map[string]string `json:"source_sha256"`
		Cases  []struct {
			Case, Filesystem string
			Outcomes         replacementNativeOutcome `json:"native"`
			Source           map[string]any           `json:"source_metadata"`
			Replacement      map[string]any           `json:"replacement_metadata"`
			Copy             map[string]any           `json:"native_metadata"`
			PayloadMatches   bool                     `json:"copyfile_payload_matches"`
			SourceUnchanged  bool                     `json:"source_unchanged"`
			Removed          bool                     `json:"staging_removed"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Schema != 1 || len(fixture.Cases) != 8 {
		t.Fatalf("incomplete native fixture: schema %d cases %d", fixture.Schema, len(fixture.Cases))
	}
	referenceSources, referenceErr := captureprovenance.Reference(os.DirFS("../.."), fixture.Hashes)
	if referenceErr != nil {
		t.Fatal(referenceErr)
	}
	if err := captureprovenance.Verify(referenceSources, fixture.Hashes); err != nil {
		t.Fatal(err)
	}
	source, err := captureprovenance.ReadSource(referenceSources, fixture.Hashes, "testdata/appledouble/native/replacement-copy.c")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(source)
	if fixture.Hashes["testdata/appledouble/native/replacement-copy.c"] != hex.EncodeToString(digest[:]) {
		t.Fatal("native C source hash mismatch")
	}
	seen := map[string]bool{}
	for _, record := range fixture.Cases {
		key := record.Filesystem + "/" + record.Case
		if seen[key] {
			t.Fatalf("duplicate native record: %s", key)
		}
		seen[key] = true
		t.Run(key, func(t *testing.T) {
			if record.Filesystem != "APFS" && record.Filesystem != "HFS+" {
				t.Fatal("unqualified filesystem")
			}
			cloneErr := record.Outcomes.CloneErrno
			want := 0
			if record.Filesystem == "HFS+" {
				want = 45
			} // Darwin ENOTSUP, captured on the native host.
			if cloneErr != want {
				t.Fatalf("clone errno=%d want=%d", cloneErr, want)
			}
			if err := record.Outcomes.CopyErrno; err != 0 {
				t.Fatalf("copyfile errno=%d", err)
			}
			if !record.PayloadMatches || !record.SourceUnchanged || !record.Removed {
				t.Fatal("failed native lifecycle")
			}
			if record.Source == nil || !reflect.DeepEqual(record.Source, record.Replacement) {
				t.Fatal("replacement metadata changed")
			}
			for _, field := range []string{"Mode", "UID", "GID", "Flags", "ForkSize", "ForkSHA256"} {
				if record.Source[field] == nil || !reflect.DeepEqual(record.Source[field], record.Copy[field]) {
					t.Fatalf("native copy mismatch: %s", field)
				}
			}
			attributes := func(value any) map[string]string {
				m, ok := value.(map[string]any)
				if !ok {
					t.Fatal("missing attribute map")
				}
				result := map[string]string{}
				for name, raw := range m {
					s, ok := raw.(string)
					if !ok {
						t.Fatal("invalid attribute bytes")
					}
					result[name] = s
				}
				return result
			}
			replacementNativeAttributes(t, attributes(record.Source["Attributes"]), attributes(record.Copy["Attributes"]), record.Outcomes)

			if record.Source["ForkSize"] != float64(MaxXattrReadSize+37) || record.Source["ForkSHA256"] != "403ace7ea43715da12562603d3abd9a6df0bf46f8d14011abd84d71cd8239ca8" {
				t.Fatal("large fork fixture changed")
			}
			if strings.HasSuffix(record.Case, "deny-write-true") && record.Source["ACL"] == nil {
				t.Fatal("deny-write case lacks ACL")
			}
		})
	}
	for _, filesystem := range []string{"APFS", "HFS+"} {
		for _, variant := range []string{"path", "root"} {
			for _, deny := range []string{"false", "true"} {
				key := filesystem + "/TestReplacementCopyDarwinNative/" + variant + "/deny-write-" + deny
				if !seen[key] {
					t.Fatalf("missing native case: %s", key)
				}
			}
		}
	}
}
