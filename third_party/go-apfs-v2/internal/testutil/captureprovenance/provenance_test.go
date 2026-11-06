package captureprovenance

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

func fixture() fstest.MapFS {
	source := fstest.MapFS{}
	for _, name := range append(append([]string{}, implementation...), "internal/testutil/cirunner/command.go", "internal/testutil/cirunner/command_windows.go", "internal/testutil/cirunner/command_test.go", "internal/testutil/cirunner/testdata/payload.bin", "scripts/ci-run.go", ".github/actions/setup-ci-runner/action.yml") {
		source[name] = &fstest.MapFile{Data: []byte(name + "\r\nexact\x00bytes")}
	}
	return source
}

func TestInventoryAndArtifactBytes(t *testing.T) {
	source := fixture()
	expected, err := Inventory(source)
	if err != nil {
		t.Fatal(err)
	}
	if len(expected) != len(source) {
		t.Fatalf("inventory %d want %d", len(expected), len(source))
	}
	recorded := map[string]string{"probe.c": "native-hash"}
	dir := t.TempDir()
	if err = Bind(source, dir, recorded); err != nil {
		t.Fatal(err)
	}
	if len(recorded) != len(expected)+1 || recorded["probe.c"] != "native-hash" {
		t.Fatal("native entries changed")
	}
	if err = Verify(source, recorded); err != nil {
		t.Fatal(err)
	}
	if err = Bind(source, dir, recorded); err != nil {
		t.Fatal("identical rebinding", err)
	}
	for name, input := range source {
		actual, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil || string(actual) != string(input.Data) {
			t.Fatalf("artifact %s: %q %v", name, actual, err)
		}
	}
	// Every required input is mandatory, including non-Go fixtures and all platforms.
	for name := range expected {
		t.Run(name, func(t *testing.T) {
			bad := map[string]string{}
			for k, v := range recorded {
				bad[k] = v
			}
			delete(bad, name)
			if err := Verify(source, bad); err == nil {
				t.Fatal("missing source accepted")
			}
			bad[name] = strings.Repeat("0", 64)
			if err := Verify(source, bad); err == nil {
				t.Fatal("stale source accepted")
			}
		})
	}
	for _, name := range []string{"internal/testutil/cirunner/invented.go", "internal/testutil/captureprovenance/invented.go"} {
		recorded[name] = "invented"
		if err := Verify(source, recorded); err == nil {
			t.Fatal("unexpected source accepted")
		}
		delete(recorded, name)
	}
}

type changedFS struct {
	fstest.MapFS
	calls   map[string]int
	failure bool
}

func (s *changedFS) ReadFile(name string) ([]byte, error) {
	s.calls[name]++
	if name == implementation[0] && s.calls[name] > 1 {
		if s.failure {
			return nil, fs.ErrPermission
		}
		return []byte("changed after hashing"), nil
	}
	return fs.ReadFile(s.MapFS, name)
}
func TestBindRejectsPartialProvenance(t *testing.T) {
	for _, kind := range []string{"empty-dir", "nil-map", "missing-source", "conflict", "mkdir", "write", "raced-source", "read-failure"} {
		t.Run(kind, func(t *testing.T) {
			source := fixture()
			var input fs.FS = source
			recorded := map[string]string{"probe.c": "native"}
			dir := t.TempDir()
			switch kind {
			case "empty-dir":
				dir = ""
			case "nil-map":
				recorded = nil
			case "missing-source":
				delete(source, "scripts/ci-run.go")
			case "conflict":
				recorded[implementation[0]] = "wrong"
			case "mkdir":
				dir = filepath.Join(dir, "file")
				if err := os.WriteFile(dir, []byte("occupied"), 0600); err != nil {
					t.Fatal(err)
				}
			case "write":
				if err := os.MkdirAll(filepath.Join(dir, implementation[0]), 0700); err != nil {
					t.Fatal(err)
				}
			case "raced-source", "read-failure":
				input = &changedFS{MapFS: source, calls: map[string]int{}, failure: kind == "read-failure"}
			}
			before := map[string]string{}
			for k, v := range recorded {
				before[k] = v
			}
			if recorded == nil {
				before = nil
			}
			err := Bind(input, dir, recorded)
			if err == nil {
				t.Fatal("failure accepted")
			}
			if kind == "read-failure" && !errors.Is(err, fs.ErrPermission) {
				t.Fatal("lost read error", err)
			}
			if !reflect.DeepEqual(before, recorded) {
				t.Fatal("partial source map published")
			}
		})
	}
	broken := fixture()
	delete(broken, "scripts/ci-run.go")
	if err := Verify(broken, map[string]string{}); err == nil {
		t.Fatal("incomplete current inventory accepted")
	}
}
