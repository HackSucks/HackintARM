package hostdata

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func backingMode(t *testing.T, name string) os.FileMode {
	t.Helper()
	info, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode()
}

func backingErrors(steps []HeldLifecycleStep) error {
	var err error
	for _, step := range steps {
		err = errors.Join(err, step.Err)
	}
	return err
}

type backingOpaqueInfo struct{ os.FileInfo }

func TestAppleDoublePathReadonlyBackingRoundTrip(t *testing.T) {
	dir := t.TempDir()
	source, packed := filepath.Join(dir, "source"), filepath.Join(dir, "packed")
	for _, name := range []string{source, packed} {
		if err := os.WriteFile(name, []byte("original bytes"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(packed, 0444); err != nil {
		t.Fatal(err)
	}
	mode := backingMode(t, packed)
	objects := pathCapturedFixture(t, objectFixture(t, objectAttr("user.example", "preserved")), objectFixture(t))
	opts := AppleDoublePathOptions{Operation: PathPackAppleDouble, Pack: DefaultObjectPackOptions(), MaxOpenAttempts: 4, Captured: objects}
	result, err := CopyAppleDoublePath(context.Background(), source, packed, opts)
	if err != nil || !result.Lifecycle.Completed || backingMode(t, packed) != mode {
		t.Fatalf("readonly pack: %+v %v", result, err)
	}
	for _, outcome := range []string{"success", "malformed", "cancel"} {
		t.Run(outcome, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, []byte("payload survives"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(target, 0444); err != nil {
				t.Fatal(err)
			}
			originalMode := backingMode(t, target)
			input := packed
			if outcome == "malformed" {
				input = filepath.Join(t.TempDir(), "malformed")
				if err := os.WriteFile(input, []byte("invalid sidecar"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			unpack := DefaultObjectUnpackOptions()
			if outcome == "cancel" {
				unpack.Callback = func(UnpackNotice) CopyPipelineAction { cancel(); return CopyPipelineContinue }
			}
			captured := pathCapturedFixture(t, objects.Destination, objectFixture(t))
			result, err := CopyAppleDoublePath(ctx, input, target, AppleDoublePathOptions{Operation: PathUnpackAppleDouble, Unpack: unpack, MaxOpenAttempts: 4, Captured: captured})
			if outcome == "success" && (err != nil || !result.Lifecycle.Completed) {
				t.Fatal(result, err)
			}
			if outcome != "success" && err == nil {
				t.Fatal("failure was concealed", result)
			}
			if outcome == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if backingMode(t, target) != originalMode {
				t.Fatal("receiving-host mode was not restored")
			}
			data, err := os.ReadFile(target)
			if err != nil || string(data) != "payload survives" {
				t.Fatalf("payload %q: %v", data, err)
			}
			if outcome == "success" {
				_, attrs, err := captured.Destination.LogicalSnapshot()
				if err != nil || len(attrs) != 1 || attrs[0].Name != "user.example" {
					t.Fatal(attrs, err)
				}
			}
		})
	}
}

func TestAppleDoublePathBackingAcquisitionFailures(t *testing.T) {
	marker := errors.New("backing acquisition failed")
	for _, fault := range []string{"info", "unidentified", "open", "chmod", "reopen", "held-stat", "identity", "close", "symlink", "repeat"} {
		t.Run(fault, func(t *testing.T) {
			p := pathQualification(t)
			name := p.destinationName
			if fault == "reopen" {
				if err := os.Chmod(name, 0444); err != nil {
					t.Fatal(err)
				}
			}
			original := backingMode(t, name)
			open := p.access.open
			var statError error
			switch fault {
			case "info":
				p.access.info = func(string, bool) (os.FileInfo, error) { return nil, marker }
			case "unidentified":
				p.access.info = func(name string, _ bool) (os.FileInfo, error) {
					info, err := os.Stat(name)
					return backingOpaqueInfo{info}, err
				}
			case "open":
				p.access.open = func(string, int, uint32, bool, bool, int) (*os.File, error) { return nil, marker }
			case "chmod", "reopen":
				calls := 0
				p.access.open = func(string, int, uint32, bool, bool, int) (*os.File, error) {
					calls++
					if calls == 1 {
						return nil, os.ErrPermission
					}
					return nil, marker
				}
				if fault == "chmod" {
					p.access.chmod = func(string, os.FileMode) error { return marker }
				}
			case "held-stat":
				p.access.open = func(n string, f int, m uint32, a, b bool, c int) (*os.File, error) {
					file, err := open(n, f, m, a, b, c)
					if err != nil {
						return nil, err
					}
					if err := file.Close(); err != nil {
						t.Fatal(err)
					}
					_, statError = file.Stat()
					return file, nil
				}
			case "identity":
				p.access.open = func(_ string, f int, m uint32, a, b bool, c int) (*os.File, error) {
					return open(p.sourceName, f, m, a, b, c)
				}
			case "symlink":
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(p.sourceName, name); err != nil {
					t.Fatal(err)
				}
				p.options.NoFollowDestination = true
			}
			err := p.prepareBackingAccess()
			if (fault == "identity" || fault == "unidentified") && !errors.Is(err, ErrMetadataIdentity) {
				t.Fatal(err)
			}
			if fault == "held-stat" && (err == nil || statError == nil || err.Error() != statError.Error()) {
				t.Fatal(err, statError)
			}
			if fault == "info" || fault == "open" || fault == "chmod" || fault == "reopen" {
				if !errors.Is(err, marker) {
					t.Fatal(err)
				}
			}
			if fault == "repeat" {
				file := p.backing.file
				if err := p.prepareBackingAccess(); err != nil || p.backing.file != file {
					t.Fatal("reacquired owned backing", err)
				}
			}
			if fault == "close" {
				if err := p.backing.file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			steps := p.closeBackingAccess()
			cleanup := backingErrors(steps)
			if fault == "close" || fault == "held-stat" {
				if cleanup == nil {
					t.Fatal("close error discarded")
				}
			} else if cleanup != nil {
				t.Fatal(cleanup)
			}
			if fault != "symlink" && backingMode(t, name) != original {
				t.Fatal("backing permissions changed")
			}
		})
	}
}

func TestAppleDoublePathBackingHeldRename(t *testing.T) {
	p := pathQualification(t)
	name, moved := p.destinationName, p.destinationName+"-moved"
	if err := os.Chmod(name, 0444); err != nil {
		t.Fatal(err)
	}
	original := backingMode(t, name)
	if err := p.prepareBackingAccess(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(name, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("decoy"), 0600); err != nil {
		t.Fatal(err)
	}
	decoy := backingMode(t, name)
	if err := backingErrors(p.closeBackingAccess()); err != nil {
		t.Fatal(err)
	}
	if backingMode(t, moved) != original || backingMode(t, name) != decoy {
		t.Fatal("restoration must affect only the held original inode")
	}
}

func TestAppleDoublePathBackingSubstitutionCleanup(t *testing.T) {
	for _, held := range []bool{false, true} {
		t.Run(map[bool]string{false: "path-fallback", true: "reopened-replacement"}[held], func(t *testing.T) {
			p := pathQualification(t)
			name, moved := p.destinationName, p.destinationName+"-moved"
			if err := os.Chmod(name, 0444); err != nil {
				t.Fatal(err)
			}
			open := p.access.open
			calls := 0
			marker := errors.New("reopen failed")
			p.access.open = func(n string, f int, m uint32, a, b bool, c int) (*os.File, error) {
				calls++
				if calls == 1 {
					return nil, os.ErrPermission
				}
				if err := os.Rename(name, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, []byte("replacement"), 0600); err != nil {
					t.Fatal(err)
				}
				if !held {
					return nil, marker
				}
				return open(n, f, m, a, b, c)
			}
			err := p.prepareBackingAccess()
			if held && !errors.Is(err, ErrMetadataIdentity) || !held && !errors.Is(err, marker) {
				t.Fatal(err)
			}
			mode := backingMode(t, name)
			steps := p.closeBackingAccess()
			if !errors.Is(backingErrors(steps), ErrMetadataIdentity) {
				t.Fatal("missing cleanup identity refusal", steps)
			}
			if backingMode(t, name) != mode {
				t.Fatal("cleanup chmodded a replacement inode")
			}
			if backingMode(t, moved).Perm()&0200 == 0 {
				t.Fatal("test did not create real temporary permission change")
			}
		})
	}
}
