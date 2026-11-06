package evidenceaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"reflect"
	"testing"
	"testing/fstest"
)

func harnessSources() fstest.MapFS {
	return fstest.MapFS{
		"go.mod":                                        {Data: []byte("module qualification\n")},
		"internal/testutil/cirunner/runner.go":          {Data: []byte("package cirunner\n")},
		"internal/testutil/cirunner/runner_test.go":     {Data: []byte("package cirunner\n// test\n")},
		"internal/testutil/cirunner/process_windows.go": {Data: []byte("package cirunner\r\n")},
		"internal/testutil/cirunner/process_linux.go":   {Data: []byte("package cirunner\n// linux\n")},
		"internal/testutil/cirunner/process_darwin.go":  {Data: []byte("package cirunner\n// darwin\n")},
		"internal/testutil/cirunner/native/abi.h":       {Data: []byte("// exact header\n")},
		"internal/testutil/cirunner/native/abi.s":       {Data: []byte("// exact assembly\n")},
		"internal/testutil/cirunner/testdata/input.txt": {Data: []byte("exact fixture\n")},
		"scripts/ci-run.go":                             {Data: []byte("package main\n")},
		".github/actions/setup-ci-runner/action.yml":    {Data: []byte("name: setup\n")},
	}
}

func TestHarnessSourceHashesCompleteInventory(t *testing.T) {
	source := harnessSources()
	want := map[string]string{}
	for name, file := range source {
		digest := sha256.Sum256(file.Data)
		want[name] = hex.EncodeToString(digest[:])
	}
	// Capacity beyond the supplied slice must remain owned by the caller.
	backing := []string{"go.mod", "untouched-one", "untouched-two"}
	got, err := HarnessSourceHashes(source, backing[:1])
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("complete cross-platform inventory: %v want %v: %v", got, want, err)
	}
	if !reflect.DeepEqual(backing, []string{"go.mod", "untouched-one", "untouched-two"}) {
		t.Fatal("caller pattern storage modified")
	}
	duplicate, err := HarnessSourceHashes(source, []string{"go.mod", "internal/testutil/cirunner/runner.go"})
	if err != nil || !reflect.DeepEqual(duplicate, want) {
		t.Fatal("duplicate inputs changed evidence", err)
	}
	for name := range want {
		t.Run(name, func(t *testing.T) {
			changed := harnessSources()
			changed[name].Data = append(changed[name].Data, '!')
			actual, err := HarnessSourceHashes(changed, []string{"go.mod"})
			if err != nil || len(actual) != len(want) || actual[name] == want[name] {
				t.Fatal("changed dependency did not change its digest", err)
			}
			for other, expected := range want {
				if other != name && actual[other] != expected {
					t.Fatal("unrelated dependency digest changed", other)
				}
			}
		})
	}
}

func TestHarnessSourceHashesRequiredInputs(t *testing.T) {
	for _, name := range []string{"scripts/ci-run.go", ".github/actions/setup-ci-runner/action.yml", "go.mod", "runner-tree", "top-level-go"} {
		t.Run(name, func(t *testing.T) {
			source := harnessSources()
			switch name {
			case "runner-tree":
				for path := range source {
					if len(path) >= len("internal/testutil/cirunner/") && path[:len("internal/testutil/cirunner/")] == "internal/testutil/cirunner/" {
						delete(source, path)
					}
				}
			case "top-level-go":
				matches, err := fs.Glob(source, "internal/testutil/cirunner/*.go")
				if err != nil {
					t.Fatal(err)
				}
				for _, path := range matches {
					delete(source, path)
				}
			default:
				delete(source, name)
			}
			if got, err := HarnessSourceHashes(source, []string{"go.mod"}); got != nil || !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("incomplete inventory accepted", got, err)
			}
		})
	}
	if got, err := HarnessSourceHashes(harnessSources(), []string{"["}); got != nil || err == nil {
		t.Fatal("malformed caller pattern accepted", got, err)
	}
	// The additive API must not make generic source hashing depend on a runner.
	if got, err := SourceHashes(fstest.MapFS{"source": {Data: []byte("data")}}, []string{"source"}); err != nil || len(got) != 1 {
		t.Fatal("generic source hashing changed", got, err)
	}
}

type harnessFaultFS struct {
	fs.FS
	path string
	err  error
}

func (f harnessFaultFS) Stat(name string) (fs.FileInfo, error) {
	return fs.Stat(f.FS, name)
}

func (f harnessFaultFS) Open(name string) (fs.File, error) {
	if name == f.path {
		return nil, f.err
	}
	return f.FS.Open(name)
}

func TestHarnessSourceHashesReadFailures(t *testing.T) {
	fault := errors.New("source read fault")
	for _, name := range []string{"internal/testutil/cirunner", "internal/testutil/cirunner/native", "internal/testutil/cirunner/native/abi.h", "scripts/ci-run.go"} {
		t.Run(name, func(t *testing.T) {
			source := harnessFaultFS{FS: harnessSources(), path: name, err: fault}
			if got, err := HarnessSourceHashes(source, []string{"go.mod"}); got != nil || !errors.Is(err, fault) {
				t.Fatal("source failure lost or partial provenance returned", got, err)
			}
		})
	}
}
