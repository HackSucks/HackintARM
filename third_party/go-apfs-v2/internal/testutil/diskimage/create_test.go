package diskimage

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"howett.net/plist"
)

func imageInventory(t *testing.T, path, device string) []byte {
	t.Helper()
	images := []any{}
	if path != "" {
		images = append(images, map[string]any{"image-path": path, "system-entities": []any{map[string]any{"dev-entry": device}}})
	}
	data, err := plist.Marshal(map[string]any{"images": images}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func noImageWait(context.Context, time.Duration) error { return nil }

func TestCreateBusyLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "native.dmg")
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(parent, filepath.Base(path))
	failure := errors.New("native busy")
	creates, detaches, inspections, pauses := 0, 0, 0, 0
	command := func(args ...string) ([]byte, []byte, error) {
		switch args[0] {
		case "create":
			creates++
			if len(args) != 8 || args[2] != "128m" || args[4] != "APFS" || args[6] != "FIXTURE" || args[7] != path {
				t.Fatal("changed create inputs", args)
			}
			if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("stale image reused", err)
			}
			if err := os.WriteFile(path, []byte("partial"), 0600); err != nil {
				t.Fatal(err)
			}
			if creates == 1 {
				return nil, []byte("hdiutil: create failed - Resource busy\n"), failure
			}
			return nil, nil, nil
		case "info":
			inspections++
			return imageInventory(t, path, "/dev/disk77"), nil, nil
		case "detach":
			detaches++
			if len(args) != 2 || args[1] != "/dev/disk77" {
				t.Fatal("wrong eject target", args)
			}
			if detaches == 1 {
				return nil, []byte("Resource busy"), failure
			}
			return nil, nil, nil
		default:
			t.Fatal("unexpected or forced operation", args)
			return nil, nil, failure
		}
	}
	err = create(t.Context(), path, "APFS", "FIXTURE", command, func(context.Context, time.Duration) error { pauses++; return nil })
	if err != nil || creates != 2 || detaches != 2 || inspections != 1 || pauses != 2 {
		t.Fatal(err, creates, detaches, inspections, pauses)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("successful image lost", err)
	}
}

func TestCreateFailureBoundaries(t *testing.T) {
	failure := errors.New("native failure")
	for _, name := range []string{"exhausted", "ordinary", "canceled", "pause", "cleanup"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "native.dmg")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			if name == "canceled" {
				cancel()
			}
			command := func(args ...string) ([]byte, []byte, error) {
				if args[0] == "info" {
					if name == "cleanup" {
						return nil, nil, ioFailure
					}
					return imageInventory(t, "", ""), nil, nil
				}
				calls++
				diagnostic := "hdiutil: create failed - Resource busy"
				if name == "ordinary" {
					diagnostic = "hdiutil: create failed - Permission denied"
				}
				return nil, []byte(diagnostic), failure
			}
			pause := func(context.Context, time.Duration) error {
				if name == "pause" {
					cancel()
					return ctx.Err()
				}
				return nil
			}
			err := create(ctx, path, "HFS+", "NATIVE", command, pause)
			if err == nil {
				t.Fatal("failure accepted")
			}
			switch name {
			case "canceled":
				if calls != 0 || !errors.Is(err, context.Canceled) {
					t.Fatal(err, calls)
				}
			case "pause":
				if calls != 1 || !errors.Is(err, context.Canceled) || !errors.Is(err, failure) {
					t.Fatal(err, calls)
				}
			case "cleanup":
				if calls != 1 || !errors.Is(err, ioFailure) || !errors.Is(err, failure) {
					t.Fatal(err, calls)
				}
			case "exhausted":
				if calls != 10 || !errors.Is(err, failure) || !strings.Contains(err.Error(), "attempt 10") {
					t.Fatal(err, calls)
				}
			case "ordinary":
				if calls != 1 || !errors.Is(err, failure) {
					t.Fatal(err, calls)
				}
			}
		})
	}
}

var ioFailure = errors.New("cannot inspect attachments")

func TestCreateRejectsExistingAndInvalidPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "native.dmg")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	never := func(...string) ([]byte, []byte, error) { t.Fatal("unsafe create launched"); return nil, nil, nil }
	for _, value := range []struct {
		path, filesystem, volume string
		want                     error
	}{
		{path, "APFS", "NATIVE", fs.ErrExist},
		{"relative.dmg", "APFS", "NATIVE", fs.ErrInvalid},
		{filepath.Join(t.TempDir(), "wrong.img"), "APFS", "NATIVE", fs.ErrInvalid},
		{filepath.Join(t.TempDir(), "file.dmg"), "", "NATIVE", fs.ErrInvalid},
		{filepath.Join(t.TempDir(), "file.dmg"), "APFS", "", fs.ErrInvalid},
		{filepath.Join(t.TempDir(), "absent", "file.dmg"), "APFS", "NATIVE", fs.ErrNotExist},
	} {
		if err := create(t.Context(), value.path, value.filesystem, value.volume, never, noImageWait); !errors.Is(err, value.want) {
			t.Fatal(value, err)
		}
	}
	bytes, err := os.ReadFile(path)
	if err != nil || string(bytes) != "keep" {
		t.Fatal("prior image altered", err)
	}
}

func TestCreateCleanupSafety(t *testing.T) {
	for _, name := range []string{"no-file", "partial", "unrelated", "decode", "missing-inventory", "missing-device", "detach", "directory", "symlink"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "partial.dmg")
			switch name {
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("outside", path); err != nil {
					t.Fatal(err)
				}
			case "partial", "unrelated", "detach":
				if err := os.WriteFile(path, []byte("partial"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			detaches := 0
			command := func(args ...string) ([]byte, []byte, error) {
				if args[0] == "detach" {
					detaches++
					return nil, []byte("Permission denied"), ioFailure
				}
				switch name {
				case "decode":
					return []byte("corrupt"), nil, nil
				case "missing-inventory":
					return []byte("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict/></plist>"), nil, nil
				case "missing-device":
					return imageInventory(t, path, "/dev/disk7s1"), nil, nil
				case "unrelated":
					return imageInventory(t, path+".other", "/dev/disk99"), nil, nil
				case "detach":
					return imageInventory(t, path, "/dev/disk9"), nil, nil
				default:
					return imageInventory(t, "", ""), nil, nil
				}
			}
			err := cleanupCreate(t.Context(), path, command, noImageWait)
			switch name {
			case "no-file", "partial", "unrelated":
				if err != nil || detaches != 0 {
					t.Fatal(err, detaches)
				}
				if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("partial image retained", err)
				}
			case "detach":
				if !errors.Is(err, ioFailure) || detaches != 1 {
					t.Fatal(err, detaches)
				}
			default:
				if err == nil || detaches != 0 {
					t.Fatal("unsafe cleanup accepted", err, detaches)
				}
			}
		})
	}
}

// Run the public command path against a separate child process on every host;
// native hdiutil qualification remains in the macOS producer matrix.
func TestMain(m *testing.M) {
	if os.Getenv("APFS_CREATE_COMMAND_HELPER") == "1" {
		if len(os.Args) != 9 || os.Args[1] != "create" {
			os.Exit(64)
		}
		if err := os.WriteFile(os.Args[8], []byte("created by command helper"), 0600); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}
func TestCreatePublicCommand(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	name := "hdiutil"
	if filepath.Ext(executable) == ".exe" {
		name += ".exe"
	}
	if err := os.WriteFile(filepath.Join(directory, name), content, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("APFS_CREATE_COMMAND_HELPER", "1")
	path := filepath.Join(directory, "created.dmg")
	if err := Create(t.Context(), path, "APFS", "TEST"); err != nil {
		t.Fatal(err)
	}
	content, err = os.ReadFile(path)
	if err != nil || string(content) != "created by command helper" {
		t.Fatal("command result lost", err)
	}
}
