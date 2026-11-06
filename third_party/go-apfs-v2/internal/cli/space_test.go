package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	diskspace "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/diskspace"
)

// TestRequiredScratchBytes covers the arithmetic without needing a full disk.
// The doubling is the part worth pinning: by default the scratch file and the
// DMG built from it sit on the same file system at the same time.
func TestRequiredScratchBytes(t *testing.T) {
	const image = 1000

	out := filepath.Join(t.TempDir(), "image.dmg")
	beside := filepath.Dir(out)
	elsewhere := t.TempDir()

	// Beside the output: room for the raw image and the DMG, plus headroom.
	if got, want := requiredScratchBytes(beside, out, image), uint64(2400); got != want {
		t.Errorf("scratch beside the output needs %d, want %d (2x plus %d%% headroom)", got, want, spaceHeadroom)
	}

	// Elsewhere: only the raw image lands here, so no doubling.
	if got, want := requiredScratchBytes(elsewhere, out, image), uint64(1200); got != want {
		t.Errorf("scratch on another file system needs %d, want %d (1x plus %d%% headroom)", got, want, spaceHeadroom)
	}

	// A trailing separator or an unclean path must not defeat the comparison,
	// or a same-directory build would silently under-budget by half.
	if got := requiredScratchBytes(beside+string(filepath.Separator), out, image); got != 2400 {
		t.Errorf("a trailing separator changed the estimate to %d; paths must be compared cleaned", got)
	}
}

// TestEnsureScratchSpaceAllowsWhatFits checks the common case does not trip:
// a temp directory with room takes a modest image without complaint.
func TestEnsureScratchSpaceAllowsWhatFits(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "image.dmg")

	if err := ensureScratchSpace(dir, out, 1<<20); err != nil {
		t.Errorf("a 1 MiB image was refused: %v", err)
	}
}

// TestEnsureScratchSpaceRefusesTheImpossible checks an image larger than the
// file system is caught. The size is chosen to exceed any real disk, so the
// test needs no special environment.
func TestEnsureScratchSpaceRefusesTheImpossible(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "image.dmg")

	available, ok, err := diskspace.AvailableSpace(dir)
	if err != nil || !ok {
		t.Skip("this platform cannot report free space, so the guard is inactive")
	}
	t.Logf("%s has %s available", dir, formatSize(available))

	const petabyte = 1 << 50
	err = ensureScratchSpace(dir, out, petabyte)
	if err == nil {
		t.Fatal("a 1 PiB image was accepted")
	}
	if code := exitCodeFor(err); code != ExitError {
		t.Errorf("exit code = %d, want %d", code, ExitError)
	}
	// The message has to be actionable: what was needed, what there is, and
	// what to do about it.
	for _, want := range []string{"not enough space", "available", "--temp-dir"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}

// TestEnsureScratchSpaceIsAdvisory checks an unmeasurable size does not block
// a build. Refusing to work because we could not measure would be worse than
// the problem being guarded against.
func TestEnsureScratchSpaceIsAdvisory(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "image.dmg")

	if err := ensureScratchSpace(dir, out, 0); err != nil {
		t.Errorf("an unknown image size was refused: %v", err)
	}
	// A directory that cannot be queried must not block either.
	if err := ensureScratchSpace(filepath.Join(dir, "absent"), out, 1<<20); err != nil {
		t.Errorf("an unqueryable directory was refused: %v", err)
	}
}

// TestSourceTreeBytes checks the estimate counts regular file content and
// nothing else, since that is what the image will actually hold.
func TestSourceTreeBytes(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "a.bin"), make([]byte, 1000), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "b.bin"), make([]byte, 2000), 0644); err != nil {
		t.Fatal(err)
	}
	// A symbolic link must not be counted as its target's size.
	if err := os.Symlink("a.bin", filepath.Join(dir, "link")); err != nil {
		t.Skipf("unable to create a symlink: %v", err)
	}

	got, err := sourceTreeBytes(dir)
	if err != nil {
		t.Fatalf("sourceTreeBytes: %v", err)
	}
	if got != 3000 {
		t.Errorf("sourceTreeBytes = %d, want 3000 (regular file content only)", got)
	}
}
