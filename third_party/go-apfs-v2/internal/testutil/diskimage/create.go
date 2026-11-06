package diskimage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/cirunner"
	"howett.net/plist"
)

// Create creates a fresh, harness-owned image. Resource-busy failures are retried
// at most ten times, after inspecting and ordinarily detaching only attachments
// belonging to this exact image. Every command is reported by cirunner. Existing
// paths, ambiguous attachments, failed cleanup and other errors are fatal.
func Create(ctx context.Context, path, filesystem, volume string) error {
	return create(ctx, path, filesystem, volume, func(args ...string) ([]byte, []byte, error) {
		var stderr bytes.Buffer
		cmd := cirunner.CommandContext(ctx, "hdiutil", args...)
		cmd.Stderr = &stderr
		output, err := cmd.Output()
		return output, stderr.Bytes(), err
	}, wait)
}

type imageCommand func(...string) ([]byte, []byte, error)

func create(ctx context.Context, path, filesystem, volume string, command imageCommand, pause func(context.Context, time.Duration) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !filepath.IsAbs(path) || filepath.Ext(path) != ".dmg" || filesystem == "" || volume == "" {
		return fs.ErrInvalid
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		if err == nil {
			return fs.ErrExist
		}
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return err
	}
	path = filepath.Join(parent, filepath.Base(path))
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, diagnostic, err := command("create", "-size", "128m", "-fs", filesystem, "-volname", volume, path)
		if err == nil {
			return nil
		}
		failure := fmt.Errorf("create image attempt %d: %w: %s", attempt, err, diagnostic)
		// hdiutil reports EBUSY as exit 1; match its exact terminal diagnostic,
		// never retry arbitrary filesystem, permission or image-format failures.
		if !strings.Contains(string(diagnostic), "hdiutil: create failed - Resource busy") {
			return failure
		}
		if cleanupErr := cleanupCreate(ctx, path, command, pause); cleanupErr != nil {
			return errors.Join(failure, cleanupErr)
		}
		if attempt == 10 {
			return failure
		}
		if err = pause(ctx, time.Second); err != nil {
			return errors.Join(failure, err)
		}
	}
}

func cleanupCreate(ctx context.Context, path string, command imageCommand, pause func(context.Context, time.Duration) error) error {
	output, diagnostic, err := command("info", "-plist")
	if err != nil {
		return fmt.Errorf("inspect failed image attachments: %w: %s", err, diagnostic)
	}
	var report struct {
		Images []struct {
			Path     string `plist:"image-path"`
			Entities []struct {
				Device string `plist:"dev-entry"`
			} `plist:"system-entities"`
		} `plist:"images"`
	}
	if _, err = plist.Unmarshal(output, &report); err != nil {
		return fmt.Errorf("decode image attachments: %w", err)
	}
	if report.Images == nil {
		return fmt.Errorf("missing attachment inventory: %w", fs.ErrInvalid)
	}
	for _, image := range report.Images {
		if filepath.Clean(image.Path) != filepath.Clean(path) {
			continue
		}
		device := ""
		for _, entity := range image.Entities {
			if wholeDevice.MatchString(entity.Device) {
				device = entity.Device
				break
			}
		}
		if device == "" {
			return fmt.Errorf("failed image has no backing device: %w", fs.ErrInvalid)
		}
		if err = retryDetach(ctx, func() (int, error) {
			_, diagnostic, err := command("detach", device)
			if err == nil {
				return 0, nil
			}
			// Only the ordinary busy detach can be retried; other diagnostics retain
			// their original error and fail. No force detach is issued.
			if strings.Contains(string(diagnostic), "Resource busy") {
				return 16, err
			}
			return -1, err
		}, pause); err != nil {
			return err
		}
	}
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("failed image is not regular: %w", fs.ErrInvalid)
	}
	return os.Remove(path)
}
