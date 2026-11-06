package evidenceaudit

import (
	"strings"
	"testing"
	"testing/fstest"

	"go.yaml.in/yaml/v3"
)

func graphFixture() (fstest.MapFS, string, []string) {
	entry := ".github/workflows/ci.yml"
	families := []string{".github/workflows/native.yml"}
	root := `on:
  push:
  pull_request:
jobs:
  native:
    uses: ./.github/workflows/native.yml
  coverage:
    runs-on: ubuntu-latest
  complete:
    if: always()
    needs: [native, coverage]
    steps:
      - env:
          RESULTS: ${{ toJSON(needs) }}
        run: |
          printf '%s\n' "$RESULTS" | jq -e 'all(.[]; .result == "success")'
`
	return fstest.MapFS{entry: {Data: []byte(root)}, families[0]: {Data: []byte("on:\n  workflow_call:\njobs:\n  capture:\n    runs-on: macos-15\n")}}, entry, families
}

func TestQualificationGraphRejectsMissingDuplicateAndConditionalGates(t *testing.T) {
	source, entry, families := graphFixture()
	if err := QualificationGraph(source, entry, "complete", families); err != nil {
		t.Fatal(err)
	}
	root := string(source[entry].Data)
	child := string(source[families[0]].Data)
	for _, change := range []struct{ path, from, to string }{
		{entry, "on:\n  push:\n  pull_request:", "on: [push, pull_request]"},
		{entry, "  pull_request:", "  workflow_dispatch:"},
		{entry, "jobs:", "invalid: ["},
		{entry, "jobs:", "empty-jobs:"},
		{entry, "./.github/workflows/native.yml", "./.github/workflows/unknown.yml"},
		{entry, "    uses: ./.github/workflows/native.yml", "    if: false\n    uses: ./.github/workflows/native.yml"},
		{entry, "  coverage:\n    runs-on: ubuntu-latest", "  coverage:\n    uses: ./.github/workflows/native.yml"},
		{entry, "    uses: ./.github/workflows/native.yml", "    runs-on: ubuntu-latest"},
		{entry, "if: always()", "if: success()"},
		{entry, "  complete:", "  other-gate:"},
		{entry, "needs: [native, coverage]", "needs: [native]"},
		{entry, "needs: [native, coverage]", "needs: [native, native]"},
		{entry, "needs: [native, coverage]", "needs: [native, missing]"},
		{entry, "needs: [native, coverage]", "needs: [native, complete]"},
		{entry, "needs: [native, coverage]", "needs: {native: true}"},
		{entry, "${{ toJSON(needs) }}", "invented"},
		{entry, ".result == \"success\"", ".result != \"failure\""},
		{families[0], "  workflow_call:", "  pull_request:"},
		{families[0], "  workflow_call:", "  workflow_call:\n  push:"},
		{families[0], "on:\n  workflow_call:", "on: workflow_call"},
	} {
		source[entry].Data = []byte(root)
		source[families[0]].Data = []byte(child)
		source[change.path].Data = []byte(strings.Replace(string(source[change.path].Data), change.from, change.to, 1))
		if err := QualificationGraph(source, entry, "complete", families); err == nil {
			t.Fatal("invalid graph accepted", change.from, change.to)
		}
	}
	source, entry, families = graphFixture()
	for _, inventory := range [][]string{nil, {families[0], families[0]}, {"../outside"}, {entry}, {"missing"}} {
		if err := QualificationGraph(source, entry, "complete", inventory); err == nil {
			t.Fatal("invalid family inventory accepted", inventory)
		}
	}
	if err := QualificationGraph(source, "missing", "complete", families); err == nil {
		t.Fatal("missing entry accepted")
	}
	for _, node := range []yaml.Node{{Kind: yaml.MappingNode}, {Kind: yaml.SequenceNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}} {
		if _, err := graphNeeds(node); err == nil {
			t.Fatal("invalid dependencies accepted")
		}
	}
	for _, node := range []yaml.Node{{}, {Kind: yaml.ScalarNode, Value: "native"}} {
		if _, err := graphNeeds(node); err != nil {
			t.Fatal(err)
		}
	}
}
