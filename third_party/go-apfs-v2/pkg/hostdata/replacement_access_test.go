package hostdata

import (
	"bytes"
	"errors"
	"os"

	"runtime"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

// Exercise a real host write denial through both public APIs on every OS.
// The private staging copy must be writable, then regain the source denial.
func TestReplacementWriteDeniedSource(t *testing.T) {
	replacementVariants(t, func(t *testing.T, prepare func(*os.File, string) (*testedReplacement, error)) {
		source := heldfixture.Source(t, 0600)
		original, err := os.ReadFile(source.Name())
		if err != nil {
			t.Fatal(err)
		}
		switch runtime.GOOS {
		case "darwin":
			if out, err := cirunner.Command("/bin/chmod", "+a", "everyone deny write", source.Name()).CombinedOutput(); err != nil {
				t.Fatalf("set source denial: %v %s", err, out)
			}
		case "windows":
			if out, err := cirunner.Command("icacls", source.Name(), "/deny", "*S-1-1-0:(WD)").CombinedOutput(); err != nil {
				t.Fatalf("set source denial: %v %s", err, out)
			}
		default:
			if err := source.Chmod(0400); err != nil {
				t.Fatal(err)
			}
		}
		denied := func(path string) {
			t.Helper()
			f, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err == nil {
				f.Close()
				t.Fatal("write denial ineffective", path)
			}
			if !errors.Is(err, os.ErrPermission) {
				t.Fatal("expected permission failure", err)
			}
		}
		denied(source.Name())
		parent := t.TempDir()
		r, err := prepare(source, parent)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = r.Close() })
		if _, err := r.File.WriteAt([]byte("new contents"), 0); err != nil {
			t.Fatal(err)
		}
		if err := r.File.Truncate(12); err != nil {
			t.Fatal(err)
		}
		if err := r.RestoreMetadata(); err != nil {
			t.Fatal(err)
		}
		denied(source.Name())
		denied(r.File.Name())
		got, err := os.ReadFile(r.File.Name())
		if err != nil || string(got) != "new contents" {
			t.Fatal(string(got), err)
		}
		got, err = os.ReadFile(source.Name())
		if err != nil || !bytes.Equal(got, original) {
			t.Fatal("source changed", err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(parent)
		if err != nil || len(entries) != 0 {
			t.Fatal("staging leaked", entries, err)
		}
	})
}
