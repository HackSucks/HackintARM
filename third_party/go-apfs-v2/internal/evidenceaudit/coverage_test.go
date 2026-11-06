package evidenceaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"testing/fstest"
)

func fixture(t *testing.T, dir string) (fstest.MapFS, fstest.MapFS, report) {
	t.Helper()
	name := "pkg/hostdata/example.go"
	if dir == "appledouble" {
		name = "pkg/appledouble/example.go"
	}
	if dir == "strict-xattrs" {
		name = "pkg/hostdata/xattr_strict.go"
	}
	data := []byte("package example\n")
	h := sha256.Sum256(data)
	r := report{Revision: "head", GOOS: "linux", Passed: 1, Covered: 20, Statements: 20, Sources: map[string]string{name: hex.EncodeToString(h[:])}, CoverageFiles: map[string][2]int64{name: {20, 20}}}
	if dir == "strict-xattrs" {
		r.CoverageFiles = nil
		r.Files = map[string]count{"xattr_strict.go": {20, 20}}
		r.Total = count{20, 20}
	}
	artifacts := fstest.MapFS{
		dir + "/coverage.out": {Data: []byte("mode: atomic\ngithub.com/deploymenttheory/go-apfs-v2/" + name + ":1.1,2.1 20 1\n")},
		dir + "/tests.jsonl":  {Data: []byte("{\"Action\":\"pass\",\"Test\":\"TestExample\"}\n{\"Action\":\"pass\"}\n")},
	}
	putReport(t, artifacts, dir, r)
	return fstest.MapFS{name: {Data: data}}, artifacts, r
}
func putReport(t *testing.T, artifacts fstest.MapFS, dir string, r report) {
	t.Helper()
	b, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	artifacts[dir+"/coverage.json"] = &fstest.MapFile{Data: b}
}

func TestCoverage(t *testing.T) {
	for _, dir := range []string{"appledouble", "strict-xattrs", "example", "compression-owned-coverage", "name-comparison-coverage", "filesystem-metadata-coverage"} {
		t.Run(dir, func(t *testing.T) {
			sources, artifacts, _ := fixture(t, dir)
			if e := Coverage(sources, artifacts, dir, "head", "linux"); e != nil {
				t.Fatal(e)
			}
		})
	}
	if len(CoverageDirectories()) != 32 {
		t.Fatal("inventory changed: update qualification expectations")
	}
	cases := []struct {
		name   string
		change func(fstest.MapFS, fstest.MapFS, *report)
	}{
		{"report missing", func(_ fstest.MapFS, a fstest.MapFS, _ *report) { delete(a, "example/coverage.json") }},
		{"report malformed", func(_ fstest.MapFS, a fstest.MapFS, _ *report) { a["example/coverage.json"].Data = []byte("{") }},
		{"revision", func(_ fstest.MapFS, _ fstest.MapFS, r *report) { r.Revision = "old" }},
		{"os", func(_ fstest.MapFS, _ fstest.MapFS, r *report) { r.GOOS = "darwin" }},
		{"no sources", func(_ fstest.MapFS, _ fstest.MapFS, r *report) { r.Sources = nil }},
		{"missing source", func(s fstest.MapFS, _ fstest.MapFS, _ *report) { delete(s, "pkg/hostdata/example.go") }},
		{"source mismatch", func(s fstest.MapFS, _ fstest.MapFS, _ *report) { s["pkg/hostdata/example.go"].Data = []byte("changed") }},
		{"transcript missing", func(_ fstest.MapFS, a fstest.MapFS, _ *report) { delete(a, "example/tests.jsonl") }},
		{"transcript malformed", func(_ fstest.MapFS, a fstest.MapFS, _ *report) { a["example/tests.jsonl"].Data = []byte("{") }},
		{"skipped", func(_ fstest.MapFS, a fstest.MapFS, _ *report) {
			a["example/tests.jsonl"].Data = []byte("{\"Action\":\"skip\"}")
		}},
		{"failed", func(_ fstest.MapFS, a fstest.MapFS, _ *report) {
			a["example/tests.jsonl"].Data = []byte("{\"Action\":\"fail\"}")
		}},
		{"truncated", func(_ fstest.MapFS, a fstest.MapFS, _ *report) {
			a["example/tests.jsonl"].Data = []byte("{\"Action\":\"pass\",\"Test\":\"TestExample\"}")
		}},
		{"no tests", func(_ fstest.MapFS, a fstest.MapFS, r *report) {
			a["example/tests.jsonl"].Data = []byte("{\"Action\":\"pass\"}")
			r.Passed = 0
		}},
		{"test counts", func(_ fstest.MapFS, _ fstest.MapFS, r *report) { r.Passed = 2 }},
		{"profile missing", func(_ fstest.MapFS, a fstest.MapFS, _ *report) { delete(a, "example/coverage.out") }},
		{"profile malformed", func(_ fstest.MapFS, a fstest.MapFS, _ *report) { a["example/coverage.out"].Data = []byte("invalid") }},
		{"empty file inventory", func(_ fstest.MapFS, _ fstest.MapFS, r *report) { r.CoverageFiles = nil }},
		{"file count mismatch", func(_ fstest.MapFS, _ fstest.MapFS, r *report) {
			r.CoverageFiles["pkg/hostdata/example.go"] = [2]int64{19, 20}
		}},
		{"total mismatch", func(_ fstest.MapFS, _ fstest.MapFS, r *report) { r.Covered = 19 }},
		{"source absent from manifest", func(s fstest.MapFS, _ fstest.MapFS, r *report) {
			r.Sources["other.go"] = r.Sources["pkg/hostdata/example.go"]
			s["other.go"] = s["pkg/hostdata/example.go"]
			delete(r.Sources, "pkg/hostdata/example.go")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, a, r := fixture(t, "example")
			tc.change(s, a, &r)
			if tc.name != "report missing" && tc.name != "report malformed" {
				putReport(t, a, "example", r)
			}
			if e := Coverage(s, a, "example", "head", "linux"); e == nil {
				t.Fatal("accepted invalid evidence")
			}
		})
	}
	for _, change := range []func(*report){func(r *report) { r.Files = nil }, func(r *report) { r.Files["xattr_strict.go"] = count{19, 20} }} {
		s, a, r := fixture(t, "strict-xattrs")
		change(&r)
		putReport(t, a, "strict-xattrs", r)
		if Coverage(s, a, "strict-xattrs", "head", "linux") == nil {
			t.Fatal("accepted incomplete strict inventory")
		}
	}
	for _, goos := range []string{"windows", "darwin"} {
		s, a, r := fixture(t, "example")
		r.GOOS = goos
		putReport(t, a, "example", r)
		if e := Coverage(s, a, "example", "head", goos); e != nil {
			t.Fatal(e)
		}
	}
	s, a, r := fixture(t, "example")
	r.GOOS = "plan9"
	putReport(t, a, "example", r)
	if Coverage(s, a, "example", "head", "plan9") == nil {
		t.Fatal("accepted unsupported OS")
	}
	if Coverage(s, a, "example", "", "linux") == nil {
		t.Fatal("accepted empty revision")
	}
}

func TestProfile(t *testing.T) {
	prefix := "github.com/deploymenttheory/go-apfs-v2/"
	good := "mode: atomic\n" + prefix + "pkg/a.go:1.1,2.1 20 0\n" + prefix + "pkg/a.go:1.1,2.1 20 2\n" + prefix + "pkg/a.go:2.1,3.1 1 0\n"
	got, e := profile([]byte(good))
	if e != nil || got["pkg/a.go"] != (count{20, 21}) {
		t.Fatalf("%v %v", got, e)
	}
	// Real Go profiles contain empty callback blocks (for example the
	// decmpfs handler's no-op release function). Repeated hit/miss blocks
	// must neither reject the report nor give it statement coverage credit.
	empty := prefix + "pkg/a.go:64.91,64.91 0 26\n" + prefix + "pkg/a.go:64.91,64.91 0 0\n"
	got, e = profile([]byte(good + empty))
	if e != nil || got["pkg/a.go"] != (count{20, 21}) {
		t.Fatalf("empty callback changed coverage: %v %v", got, e)
	}
	got, e = profile([]byte("mode: atomic\n" + empty))
	if e != nil || got["pkg/a.go"] != (count{}) || above95(got["pkg/a.go"]) {
		t.Fatalf("empty callbacks cannot satisfy coverage: %v %v", got, e)
	}
	for _, bad := range []string{"", "mode: set\n", "mode: atomic\n", "mode: atomic\ninvalid\n", "mode: atomic\nx 0 1", "mode: atomic\nx -1 1", "mode: atomic\nx 99999999999 1", "mode: atomic\nx one 1", "mode: atomic\nx 1 -1", "mode: atomic\nx 1 no", "mode: atomic\nx 1 1", "mode: atomic\nother/a.go:1.1,2.1 1 1", "mode: atomic\n" + prefix + "../a.go:1.1,2.1 1 1", good + prefix + "pkg/a.go:1.1,2.1 21 1", "mode: atomic\n" + strings.Repeat("a", 70000)} {
		if bad == "mode: atomic\n" {
			continue
		}
		if _, e := profile([]byte(bad)); e == nil {
			t.Errorf("accepted %q", bad[:min(len(bad), 80)])
		}
	}
	for _, c := range []count{{0, 0}, {19, 20}, {21, 20}, {-1, 20}} {
		if above95(c) {
			t.Errorf("accepted %v", c)
		}
	}
	if !above95(count{20, 20}) {
		t.Fatal("rejected full coverage")
	}
}

func TestCoverageProfileErrorIdentifiesArtifact(t *testing.T) {
	sources, artifacts, _ := fixture(t, "example")
	artifacts["example/coverage.out"].Data = []byte("mode: atomic\ninvalid\n")
	err := Coverage(sources, artifacts, "example", "head", "linux")
	if err == nil || !strings.Contains(err.Error(), "example/coverage.out: invalid coverage block") {
		t.Fatalf("missing report identity in parse failure: %v", err)
	}
}
