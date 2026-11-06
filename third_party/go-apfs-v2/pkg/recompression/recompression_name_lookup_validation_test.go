package recompression

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

// Corrupted copies are validation inputs, never additional native evidence.
// The child uses the exact replay entry point used by the qualification gate.
func TestNativeNameLookupRejectsTampering(t *testing.T) {
	const childEnv = "APFS_TEST_CORRUPTED_LOOKUP_CAPTURE"
	if child := os.Getenv(childEnv); child != "" {
		replayNativeNameLookup(t, child)
		return
	}
	compressed, err := os.ReadFile(filepath.Join("..", "..", "testdata", "appledouble", "native", "name-lookup-macos27.json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	original, readErr := io.ReadAll(reader)
	if err = errors.Join(readErr, reader.Close()); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	firstVolume := func(c map[string]any) map[string]any { return c["volumes"].([]any)[0].(map[string]any) }
	native := func(c map[string]any) map[string]any { return firstVolume(c)["native"].(map[string]any) }
	firstCase := func(c map[string]any) map[string]any { return native(c)["cases"].([]any)[0].(map[string]any) }
	currentHarness, err := captureprovenance.Inventory(os.DirFS("../.."))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, want string
		edit       func(map[string]any)
	}{
		{"missing-volume", "incomplete native lookup capture", func(c map[string]any) { c["volumes"] = c["volumes"].([]any)[1:] }},
		{"unknown-volume", "unexpected/duplicate native volume", func(c map[string]any) { firstVolume(c)["volume"] = "foreign" }},
		{"duplicate-volume", "unexpected/duplicate native volume", func(c map[string]any) { c["volumes"].([]any)[1] = firstVolume(c) }},
		{"source-hash", "stale native source capture", func(c map[string]any) {
			// A modified source set cannot claim a retained archive. Supply the
			// current harness for this deliberately invalid fresh input so it
			// reaches the probe digest gate, not an unrelated historical runner.
			sources := c["source_sha256"].(map[string]any)
			for name, digest := range currentHarness {
				sources[name] = digest
			}
			sources["probe.c"] = strings.Repeat("0", 64)
		}},
		{"missing-case", "uncaptured native lookup context", func(c map[string]any) { n := native(c); n["cases"] = n["cases"].([]any)[1:] }},
		{"unknown-case", "duplicate/unexpected native lookup case", func(c map[string]any) { firstCase(c)["id"] = "invented" }},
		{"duplicate-case", "duplicate/unexpected native lookup case", func(c map[string]any) { native(c)["cases"].([]any)[1] = firstCase(c) }},
		{"query-recipe", "native query recipe mismatch", func(c map[string]any) { firstCase(c)["bytes"] = "00" }},
		{"unknown-case-policy", "uncaptured native lookup context", func(c map[string]any) { native(c)["valid"] = []any{0, 0, 0, 0} }},
		{"root-actor", "uncaptured native lookup context", func(c map[string]any) { native(c)["uid"] = 0 }},
		{"missing-security-observation", "incomplete native operation observation", func(c map[string]any) { firstCase(c)["directory"].(map[string]any)["security_observed"] = false }},
		{"contradictory-contents", "incomplete native operation observation", func(c map[string]any) { firstCase(c)["content_matches"] = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var corrupted map[string]any
			if err := json.Unmarshal(original, &corrupted); err != nil {
				t.Fatal(err)
			}
			tc.edit(corrupted)
			raw, err := json.Marshal(corrupted)
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "corrupted.json")
			if err = os.WriteFile(file, raw, 0600); err != nil {
				t.Fatal(err)
			}
			command := cirunner.CommandContext(t.Context(), binary, "-test.run=^TestNativeNameLookupRejectsTampering$", "-test.count=1")
			command.Env = append(os.Environ(), childEnv+"="+file)
			output, err := command.CombinedOutput()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != 1 || !strings.Contains(string(output), tc.want) {
				t.Fatalf("corruption was not rejected at its precise validation gate: error=%v output=%s", err, output)
			}
		})
	}
}
