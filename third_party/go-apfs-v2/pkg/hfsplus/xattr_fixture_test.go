package hfsplus_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestFixtureXattrs checks the attributes reader against the committed HFS+
// fixture -- bytes macOS wrote, rather than bytes this package synthesized.
//
// The manifest records what macOS reported for each file, so the assertion is
// that every recorded attribute is present with matching content. It is
// containment rather than equality on purpose: macOS hides com.apple.decmpfs
// and the resource fork of a compressed file from a normal listing, so the
// volume legitimately holds attributes the manifest does not name.
func TestFixtureXattrs(t *testing.T) {
	imagePath := filepath.Join("..", "..", "testdata", "cli", "hfs-basic.dmg")
	manifestPath := filepath.Join("..", "..", "testdata", "cli", "hfs-manifest.json")
	if _, err := os.Stat(imagePath); err != nil {
		t.Skipf("fixture image missing: %v", err)
	}

	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("unable to read manifest: %v", err)
	}
	var want manifest
	if err := json.Unmarshal(manifestData, &want); err != nil {
		t.Fatalf("unable to parse manifest: %v", err)
	}

	volume := openVolume(t, imagePath)

	var checked int
	for name, entry := range want.Files {
		if len(entry.Xattrs) == 0 {
			continue
		}
		got, err := volume.Xattrs(name)
		if err != nil {
			t.Errorf("Xattrs(%s): %v", name, err)
			continue
		}
		for attrName, wantAttr := range entry.Xattrs {
			value, ok := got[attrName]
			if !ok {
				t.Errorf("%s: attribute %q missing (read %v)", name, attrName, keysOf(got))
				continue
			}
			if len(value) != wantAttr.Size {
				t.Errorf("%s: attribute %q is %d bytes, want %d", name, attrName, len(value), wantAttr.Size)
				continue
			}
			sum := sha256.Sum256(value)
			if h := hex.EncodeToString(sum[:]); h != wantAttr.SHA256 {
				t.Errorf("%s: attribute %q content mismatch", name, attrName)
			}
			checked++
		}
	}

	if checked == 0 {
		t.Fatal("the manifest recorded no extended attributes; the fixture or its manifest is stale")
	}
	t.Logf("verified %d extended attributes against the manifest", checked)
}

// TestFixtureXattrShapes pins the specific record shapes the fixture exists to
// cover, so a regenerated fixture that quietly lost one is caught here rather
// than reducing coverage in silence.
func TestFixtureXattrShapes(t *testing.T) {
	imagePath := filepath.Join("..", "..", "testdata", "cli", "hfs-basic.dmg")
	if _, err := os.Stat(imagePath); err != nil {
		t.Skipf("fixture image missing: %v", err)
	}
	volume := openVolume(t, imagePath)

	// A small value, stored inside its own attribute record.
	small, err := volume.Xattrs("hello.txt")
	if err != nil {
		t.Fatalf("Xattrs(hello.txt): %v", err)
	}
	if got := string(small["com.example.test"]); got != "value42" {
		t.Errorf("com.example.test = %q, want %q", got, "value42")
	}

	// A value far too large for an inline record, so it has a fork of its own.
	big, err := volume.Xattrs("bigattr.txt")
	if err != nil {
		t.Fatalf("Xattrs(bigattr.txt): %v", err)
	}
	if len(big["com.example.big"]) != 6000 {
		t.Errorf("com.example.big is %d bytes, want 6000 (the fork-backed attribute shape is not covered)",
			len(big["com.example.big"]))
	}

	// A resource fork, which HFS+ keeps in the catalog record rather than the
	// attributes file, and which is synthesized under the name macOS uses.
	rsrc, err := volume.Xattrs("rsrc.txt")
	if err != nil {
		t.Fatalf("Xattrs(rsrc.txt): %v", err)
	}
	if got := string(rsrc["com.apple.ResourceFork"]); got != "this is the resource fork payload\n" {
		t.Errorf("com.apple.ResourceFork = %q", got)
	}

	// Attributes of a hard link come from its target's catalog record.
	linked, err := volume.Xattrs("hardlink-to-hello")
	if err != nil {
		t.Fatalf("Xattrs(hardlink-to-hello): %v", err)
	}
	if string(linked["com.example.test"]) != "value42" {
		t.Error("a hard link did not report its target's attributes")
	}

	// Directories carry attributes too.
	if _, err := volume.Xattrs("dir1"); err != nil {
		t.Errorf("Xattrs on a directory: %v", err)
	}

	// A path that does not exist must be an error, not an empty map.
	if _, err := volume.Xattrs("no-such-file"); err == nil {
		t.Error("Xattrs on a missing path returned no error")
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
