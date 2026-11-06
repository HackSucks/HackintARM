// Package evidenceaudit checks retained qualification evidence against the source
// checkout. It does not replace the native oracles that establish behavior.
package evidenceaudit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"
)

// CoverageDirectories is the portable evidence inventory. New focused gates must
// extend this list; a missing report is a qualification failure.
func CoverageDirectories() []string {
	return []string{"filesystem-metadata-coverage", "ci-reporting-coverage", "name-comparison-coverage", "compression-owned-coverage", "carrier-recompression-portable", "osversion-coverage", "compression-state-portable", "compression-lifecycle-coverage", "replacement-coverage", "path-lifecycle-coverage", "held-metadata", "decmpfs-formats-coverage", "appledouble-pack-coverage", "metadata-transport-coverage", "appledouble-stream", "appledouble", "strict-xattrs", "acl-restore", "image-security-coverage", "root-security-coverage", "mode-security-coverage", "image-acl-coverage", "image-copy-coverage", "security-volume-coverage", "security-source-coverage", "image-times-coverage", "image-flags-coverage", "image-stat-coverage", "xattr-restore-coverage", "unpack-restore-coverage", "copy-pipeline-coverage", "stat-copy-coverage"}
}

type count struct{ Covered, Statements int64 }
type report struct {
	Revision      string              `json:"revision"`
	GOOS          string              `json:"goos"`
	Passed        int                 `json:"passed_tests"`
	Covered       int64               `json:"covered"`
	Statements    int64               `json:"statements"`
	Sources       map[string]string   `json:"source_sha256"`
	CoverageFiles map[string][2]int64 `json:"coverage_files"`
	Files         map[string]count    `json:"files"`
	Total         count               `json:"total"`
}

// Coverage validates one existing focused report, its raw profile and test
// transcript. Sources and evidence are independently rooted filesystems. Revision
// is the exact tested checkout revision, including GitHub's PR merge revision.
func Coverage(sources, evidence fs.FS, dir, revision, goos string) error {
	b, err := fs.ReadFile(evidence, path.Join(dir, "coverage.json"))
	if err != nil {
		return err
	}
	var r report
	if err = json.Unmarshal(b, &r); err != nil {
		return err
	}
	if revision == "" || r.Revision != revision || r.GOOS != goos || (goos != "darwin" && goos != "linux" && goos != "windows") {
		return fmt.Errorf("%s: revision or OS mismatch", dir)
	}
	if len(r.Sources) == 0 {
		return fmt.Errorf("%s: missing source hashes", dir)
	}
	for name, want := range r.Sources {
		data, e := fs.ReadFile(sources, name)
		if e != nil {
			return e
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != want {
			return fmt.Errorf("%s: source hash mismatch: %s", dir, name)
		}
	}
	b, err = fs.ReadFile(evidence, path.Join(dir, "tests.jsonl"))
	if err != nil {
		return err
	}
	passed, packagePassed := 0, false
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var event struct{ Action, Test string }
		if err = json.Unmarshal(line, &event); err != nil {
			return err
		}
		if event.Action == "skip" || event.Action == "fail" {
			return fmt.Errorf("%s: test %s: %s", dir, event.Action, event.Test)
		}
		if event.Action == "pass" {
			if event.Test == "" {
				packagePassed = true
			} else {
				passed++
			}
		}
	}
	if !packagePassed || passed == 0 || passed != r.Passed {
		return fmt.Errorf("%s: incomplete test transcript", dir)
	}
	b, err = fs.ReadFile(evidence, path.Join(dir, "coverage.out"))
	if err != nil {
		return err
	}
	actual, err := profile(b)
	if err != nil {
		return fmt.Errorf("%s: %w", path.Join(dir, "coverage.out"), err)
	}
	selected := map[string]count{}
	switch dir {
	case "appledouble":
		for name, c := range actual {
			if strings.HasPrefix(name, "pkg/appledouble/") {
				selected[name] = c
			}
		}
	case "strict-xattrs":
		for name, c := range actual {
			if strings.HasPrefix(name, "pkg/hostdata/xattr_strict") {
				selected[name] = c
			}
		}
		if len(r.Files) != len(selected) {
			return fmt.Errorf("%s: incomplete file inventory", dir)
		}
		for name, c := range selected {
			if r.Files[path.Base(name)] != c {
				return fmt.Errorf("%s: file count mismatch: %s", dir, name)
			}
		}
		r.Covered, r.Statements = r.Total.Covered, r.Total.Statements
	default:
		if len(r.CoverageFiles) == 0 {
			return fmt.Errorf("%s: no focused files", dir)
		}
		for name := range r.CoverageFiles {
			selected[name] = actual[name]
		}
	}
	for name, want := range r.CoverageFiles {
		got := actual[name]
		if got.Covered != want[0] || got.Statements != want[1] || !above95(got) {
			return fmt.Errorf("%s: focused coverage mismatch or below gate: %s", dir, name)
		}
	}
	total := count{}
	for name, c := range selected {
		if _, ok := r.Sources[name]; !ok {
			return fmt.Errorf("%s: covered source lacks hash: %s", dir, name)
		}
		total.Covered += c.Covered
		total.Statements += c.Statements
	}
	if total.Covered != r.Covered || total.Statements != r.Statements || !above95(total) {
		return fmt.Errorf("%s: total coverage mismatch or below gate", dir)
	}
	return nil
}

func above95(c count) bool {
	return c.Statements > 0 && c.Covered >= 0 && c.Covered <= c.Statements && float64(c.Covered)/float64(c.Statements) > .95
}

func profile(data []byte) (map[string]count, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	if !scanner.Scan() || scanner.Text() != "mode: atomic" {
		return nil, fmt.Errorf("invalid coverage mode")
	}
	blocks := map[string][2]int64{}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 {
			return nil, fmt.Errorf("invalid coverage block")
		}
		n, e := strconv.ParseInt(fields[1], 10, 64)
		// Go emits zero-statement blocks for empty function bodies, including
		// callbacks. Validate their location and hits normally, but count zero
		// statements: executing one cannot improve measured coverage.
		if e != nil || n < 0 || n > 1<<30 {
			return nil, fmt.Errorf("invalid statement count")
		}
		hits, e := strconv.ParseInt(fields[2], 10, 64)
		if e != nil || hits < 0 {
			return nil, fmt.Errorf("invalid hit count")
		}
		old, exists := blocks[fields[0]]
		if exists && old[0] != n {
			return nil, fmt.Errorf("inconsistent duplicate block")
		}
		if hits > 0 || old[1] > 0 {
			hits = 1
		}
		blocks[fields[0]] = [2]int64{n, hits}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	result := map[string]count{}
	const prefix = "github.com/deploymenttheory/go-apfs-v2/"
	for location, block := range blocks {
		colon := strings.LastIndexByte(location, ':')
		if colon < 0 || !strings.HasPrefix(location, prefix) {
			return nil, fmt.Errorf("invalid coverage location")
		}
		name := strings.TrimPrefix(location[:colon], prefix)
		if !fs.ValidPath(name) {
			return nil, fmt.Errorf("invalid coverage path")
		}
		c := result[name]
		c.Statements += block[0]
		if block[1] > 0 {
			c.Covered += block[0]
		}
		result[name] = c
	}
	return result, nil
}
