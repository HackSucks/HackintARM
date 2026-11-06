package captureprovenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/nativeevidence"
)

type ExecutionReceipt struct {
	Schema    int                      `json:"schema"`
	Execution nativeevidence.Execution `json:"execution"`
	Files     map[string]string        `json:"files"`
}

func hashExecutionFile(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	return hashExecutionReader(ctx, f)
}

func hashExecutionReader(ctx context.Context, f io.ReadCloser) (string, error) {
	h := sha256.New()
	buffer := make([]byte, 64<<10)
	var err error
	for {
		if err = ctx.Err(); err != nil {
			break
		}
		var n int
		n, err = f.Read(buffer)
		_, _ = h.Write(buffer[:n])
		if err != nil {
			break
		}
	}
	if err == io.EOF {
		err = nil
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func CurrentExecution(ctx context.Context) (nativeevidence.Execution, error) {
	return currentExecution(ctx, func(args ...string) ([]byte, error) {
		return cirunner.CommandContext(ctx, "git", args...).Output()
	})
}

func currentExecution(ctx context.Context, git func(...string) ([]byte, error)) (nativeevidence.Execution, error) {
	var result nativeevidence.Execution
	revision, err := git("rev-parse", "HEAD")
	if err != nil {
		return result, err
	}
	tracked, err := git("ls-files", "-z")
	if err != nil {
		return result, err
	}
	result = nativeevidence.Execution{Repository: "deploymenttheory/go-apfs-v2", Revision: strings.TrimSpace(string(revision)), Run: os.Getenv("GITHUB_RUN_ID"), Attempt: os.Getenv("GITHUB_RUN_ATTEMPT"), Job: os.Getenv("GITHUB_JOB"), Go: runtime.Version(), Sources: map[string]string{}}
	if result.Run == "" {
		result.Run = "local"
	}
	if result.Attempt == "" {
		result.Attempt = "local"
	}
	if result.Job == "" {
		result.Job = "local"
	}
	for _, name := range strings.Split(string(tracked), "\x00") {
		if name == "" {
			continue
		}
		if !fs.ValidPath(name) {
			return result, fmt.Errorf("unsafe checkout source %q", name)
		}
		hash, err := hashExecutionFile(ctx, filepath.FromSlash(name))
		if err != nil {
			return result, err
		}
		result.Sources[name] = hash
	}
	return result, nil
}

func artifactExecutionFiles(ctx context.Context, dir string) (map[string]string, error) {
	return artifactFiles(ctx, os.DirFS(dir))
}

func artifactFiles(ctx context.Context, source fs.FS) (map[string]string, error) {
	hashes := map[string]string{}
	err := fs.WalkDir(source, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if name == "execution.json" {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("non-regular evidence artifact %s", name)
		}
		f, err := source.Open(name)
		if err != nil {
			return err
		}
		hash, err := hashExecutionReader(ctx, f)
		if err != nil {
			return err
		}
		hashes[name] = hash
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(hashes) == 0 {
		return nil, fmt.Errorf("empty native evidence artifact")
	}
	return hashes, nil
}

// SealExecution binds complete producer bytes to this run without changing the
// native report or historical expected results.
func SealExecution(ctx context.Context, dir string) error {
	path := filepath.Join(dir, "execution.json")
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("refuse stale producer receipt")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	execution, err := CurrentExecution(ctx)
	if err != nil {
		return err
	}
	files, err := artifactExecutionFiles(ctx, dir)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	return writeExecutionReceipt(f, ExecutionReceipt{1, execution, files})
}

func writeExecutionReceipt(f io.WriteCloser, receipt ExecutionReceipt) error {
	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	return errors.Join(encoder.Encode(receipt), f.Close())
}

// VerifyExecution rejects wrong revisions, attempts, toolchains, source bytes
// and artifact inventories before any consumer can use producer observations.
func VerifyExecution(ctx context.Context, dir string) error {
	b, err := os.ReadFile(filepath.Join(dir, "execution.json"))
	if err != nil {
		return err
	}
	var receipt ExecutionReceipt
	if err = json.Unmarshal(b, &receipt); err != nil {
		return err
	}
	current, err := CurrentExecution(ctx)
	if err != nil {
		return err
	}
	actual := receipt.Execution
	if receipt.Schema != 1 || actual.Job == "" || actual.Repository != current.Repository || actual.Revision != current.Revision || actual.Run != current.Run || actual.Attempt != current.Attempt || actual.Go != current.Go || !reflect.DeepEqual(actual.Sources, current.Sources) {
		return fmt.Errorf("mixed native producer execution provenance")
	}
	files, err := artifactExecutionFiles(ctx, dir)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(files, receipt.Files) {
		return fmt.Errorf("missing, changed or unexpected native producer artifacts")
	}
	return nil
}
