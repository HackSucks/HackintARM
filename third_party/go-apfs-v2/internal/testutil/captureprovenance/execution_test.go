package captureprovenance

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

func executionFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Chdir(root)
	for _, args := range [][]string{{"init", "-q"}, {"config", "user.name", "Harness test"}, {"config", "user.email", "harness@example.invalid"}} {
		if b, err := cirunner.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatal(string(b), err)
		}
	}
	if err := os.WriteFile("input.go", []byte("exact original input\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "input.go"}, {"commit", "-qm", "test: source receipt"}} {
		if b, err := cirunner.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatal(string(b), err)
		}
	}
	dir := filepath.Join(root, "evidence")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "native.json"), []byte("independent native output"), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestExecutionReceiptsBindCurrentRunAndEveryByte(t *testing.T) {
	dir := executionFixture(t)
	if err := SealExecution(t.Context(), dir); err != nil {
		t.Fatal(err)
	}
	if err := VerifyExecution(t.Context(), dir); err != nil {
		t.Fatal(err)
	}
	if err := SealExecution(t.Context(), dir); err == nil {
		t.Fatal("stale receipt overwritten")
	}
	if err := os.WriteFile(filepath.Join(dir, "native.json"), []byte("changed native result"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyExecution(t.Context(), dir); err == nil {
		t.Fatal("changed native result accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "native.json"), []byte("independent native output"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("input.go", []byte("changed source"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyExecution(t.Context(), dir); err == nil {
		t.Fatal("changed current source accepted")
	}
}

func TestExecutionRejectsMissingCorruptAndMixedReceipts(t *testing.T) {
	dir := executionFixture(t)
	if err := VerifyExecution(t.Context(), dir); err == nil {
		t.Fatal("missing receipt accepted")
	}
	if err := SealExecution(t.Context(), dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "execution.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var receipt ExecutionReceipt
	if err = json.Unmarshal(b, &receipt); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"schema", "repository", "revision", "run", "attempt", "job", "go", "files"} {
		var changed ExecutionReceipt
		if err = json.Unmarshal(b, &changed); err != nil {
			t.Fatal(err)
		}
		switch field {
		case "schema":
			changed.Schema++
		case "repository":
			changed.Execution.Repository = "wrong"
		case "revision":
			changed.Execution.Revision = "wrong"
		case "run":
			changed.Execution.Run = "wrong"
		case "attempt":
			changed.Execution.Attempt = "wrong"
		case "job":
			changed.Execution.Job = ""
		case "go":
			changed.Execution.Go = "wrong"
		case "files":
			changed.Files = nil
		}
		encoded, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, encoded, 0600); err != nil {
			t.Fatal(err)
		}
		if err = VerifyExecution(t.Context(), dir); err == nil {
			t.Fatal("mixed receipt accepted", field)
		}
	}
	if err = os.WriteFile(path, []byte("invalid JSON"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = VerifyExecution(t.Context(), dir); err == nil {
		t.Fatal("invalid receipt accepted")
	}
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_RUN_ID", "new-run")
	if err = VerifyExecution(t.Context(), dir); err == nil {
		t.Fatal("different run accepted")
	}
}

func TestExecutionIOAndCancellationFailures(t *testing.T) {
	dir := executionFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := CurrentExecution(ctx); err == nil {
		t.Fatal("cancelled execution accepted")
	}
	if _, err := artifactExecutionFiles(ctx, dir); err == nil {
		t.Fatal("cancelled artifact scan accepted")
	}
	if _, err := hashExecutionFile(ctx, filepath.Join(dir, "native.json")); err == nil {
		t.Fatal("cancelled hash accepted")
	}
	if _, err := hashExecutionFile(t.Context(), "missing"); err == nil {
		t.Fatal("missing source accepted")
	}
	if _, err := artifactExecutionFiles(t.Context(), "missing"); err == nil {
		t.Fatal("missing artifact tree accepted")
	}
	empty := t.TempDir()
	if _, err := artifactExecutionFiles(t.Context(), empty); err == nil {
		t.Fatal("empty artifact accepted")
	}
	if err := SealExecution(ctx, dir); err == nil {
		t.Fatal("cancelled sealing accepted")
	}
	if err := SealExecution(t.Context(), dir); err != nil {
		t.Fatal(err)
	}
	if err := VerifyExecution(ctx, dir); err == nil {
		t.Fatal("cancelled verification accepted")
	}
	if err := os.Remove(filepath.Join(dir, "native.json")); err != nil {
		t.Fatal(err)
	}
	if err := VerifyExecution(t.Context(), dir); err == nil {
		t.Fatal("missing producer result accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "extra"), []byte("unexpected"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyExecution(t.Context(), dir); err == nil {
		t.Fatal("unexpected producer result accepted")
	}
}
