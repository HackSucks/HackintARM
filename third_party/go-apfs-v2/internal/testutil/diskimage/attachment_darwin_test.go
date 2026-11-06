package diskimage

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
)

// Reproduce the intermediate state from a partially completed detach: volumes
// are unmounted, but the backing device still needs ejection. A mount-path retry
// fails in this state; the device captured at attach remains a valid target.
func TestDetachAfterVolumeUnmount(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	run := func(args ...string) ([]byte, error) {
		t.Helper()
		b, err := cirunner.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		t.Logf("command=%q output=%q error=%v", args, b, err)
		return b, err
	}
	mustRun := func(args ...string) []byte {
		t.Helper()
		b, err := run(args...)
		if err != nil {
			t.Fatalf("native command failed: %v", err)
		}
		return b
	}
	dir := t.TempDir()
	image, mount := filepath.Join(dir, "fixture.dmg"), filepath.Join(dir, "mount")
	if err := os.Mkdir(mount, 0700); err != nil {
		t.Fatal(err)
	}
	mustRun("hdiutil", "create", "-quiet", "-size", "32m", "-fs", "HFS+", "-volname", "DETACH-TEST", image)
	attached := mustRun("hdiutil", "attach", "-plist", "-nobrowse", "-mountpoint", mount, image)
	device, err := AttachmentDevice(attached)
	if err != nil {
		t.Fatal(err)
	}
	detached := false
	detach := func() error {
		return RetryDetach(ctx, func() (int, error) {
			_, err := run("hdiutil", "detach", device)
			if err == nil {
				return 0, nil
			}
			var status *exec.ExitError
			if errors.As(err, &status) {
				return status.ExitCode(), err
			}
			return -1, err
		})
	}
	defer func() {
		if !detached {
			if err := detach(); err != nil {
				t.Errorf("fixture detach: %v", err)
			}
		}
	}()
	mustRun("/usr/sbin/diskutil", "unmount", mount)
	if _, err := os.Stat(device); err != nil {
		t.Fatalf("backing device disappeared before detach: %v", err)
	}
	_, err = run("hdiutil", "detach", mount)
	var status *exec.ExitError
	if !errors.As(err, &status) || status.ExitCode() != 1 {
		t.Fatalf("expected missing mount target, got %v", err)
	}
	if err := detach(); err != nil {
		t.Fatal(err)
	}
	detached = true
}
