package hostdata

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func compressionPathOracle(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("APFS_COMPRESSION_PATH_EVIDENCE")
	if dir == "" {
		dir = t.TempDir()
	} else if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	source := "../../testdata/appledouble/native/compression-path-query.c"
	hashes := map[string]string{}
	for _, name := range []string{source, "../../testdata/appledouble/native/compression-policy.c", "compression_path.go", "compression_path_darwin.go", "compression_path_darwin_test.go", "compression_path_oracle_darwin_test.go"} {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		hashes[name] = hex.EncodeToString(sum[:])
	}
	run := func(name string, args ...string) []byte {
		t.Helper()
		out, err := cirunner.CommandContext(t.Context(), name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v: %s", name, err, out)
		}
		return out
	}
	host := run("sw_vers")
	sdk := strings.TrimSpace(string(run("xcrun", "--show-sdk-path")))
	compiler := run("xcrun", "clang", "--version")
	for _, arch := range []string{"arm64", "x86_64"} {
		raw := run("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-arch", arch, "-isysroot", sdk, "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=path_query_probe", source)
		var ast struct {
			Kind, Name string
			Inner      []json.RawMessage
		}
		if err := json.Unmarshal(raw, &ast); err != nil || ast.Kind != "FunctionDecl" || ast.Name != "path_query_probe" || len(ast.Inner) < 2 {
			t.Fatal("missing native query body", arch, err)
		}
		name := arch + "-compression-path-query.ast.json"
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		hashes[name] = hex.EncodeToString(sum[:])
	}
	for _, name := range []string{"sys/stat.h", "sys/xattr.h", "sys/errno.h"} {
		raw, err := os.ReadFile(filepath.Join(sdk, "usr/include", name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		hashes[name] = hex.EncodeToString(sum[:])
	}
	binary := filepath.Join(dir, "query")
	run("xcrun", "clang", "-std=c11", "-Wall", "-Wextra", "-Werror", source, "-framework", "CoreFoundation", "-lcompression", "-o", binary)
	raw, err := json.MarshalIndent(map[string]any{"host": string(host), "sdk": sdk, "compiler": string(compiler), "sources": hashes}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "provenance.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return binary
}
