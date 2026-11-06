package hostdata

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Retained native Route=PACK, SourceKind=file, DestinationKind=symlink,
// Selected=NOFOLLOW removes the failed destination and preserves its target.
func TestAppleDoublePathFailedPackRemovesNoFollowLink(t *testing.T) {
	for _, dangling := range []bool{false, true} {
		dir := t.TempDir()
		source, target, link := filepath.Join(dir, "source"), filepath.Join(dir, "target"), filepath.Join(dir, "link")
		if err := os.WriteFile(source, []byte("source"), 0600); err != nil {
			t.Fatal(err)
		}
		if !dangling {
			if err := os.WriteFile(target, []byte("target bytes"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		destination := objectFixture(t)
		destination.meta.(*LogicalMetadata).state.Stat.Mode = 0120777
		objects := pathCapturedFixture(t, objectFixture(t, objectAttr("user.example", "metadata")), destination)
		result, err := CopyAppleDoublePath(context.Background(), source, link, AppleDoublePathOptions{Operation: PathPackAppleDouble, NoFollowDestination: true, Pack: DefaultObjectPackOptions(), MaxOpenAttempts: 4, Captured: objects})
		if err == nil || result.Lifecycle.Code != -1 {
			t.Fatal(result, err)
		}
		if _, err := os.Lstat(link); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed PACK retained link: %v", err)
		}
		data, err := os.ReadFile(target)
		if dangling {
			if !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
		} else if err != nil || string(data) != "target bytes" {
			t.Fatal(string(data), err)
		}
	}
}

func TestPathOrdinaryHeldRenameAndDelete(t *testing.T) {
	name := filepath.Join(t.TempDir(), "payload")
	file, err := openPathOrdinary(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	if _, err := file.WriteString("original inode"); err != nil {
		t.Fatal(err)
	}
	renamed := name + "-renamed"
	if err := os.Rename(name, renamed); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := chmodPathBacking(file, 0444); err != nil {
		t.Fatal(err)
	}
	if err := chmodPathBacking(file, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(renamed); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("original inode"))
	if _, err := file.ReadAt(buf, 0); err != nil || string(buf) != "original inode" {
		t.Fatal(string(buf), err)
	}
	if data, err := os.ReadFile(name); err != nil || string(data) != "replacement" {
		t.Fatal(string(data), err)
	}
}
