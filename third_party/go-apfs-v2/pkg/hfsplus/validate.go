// Checking a caller-supplied Entry tree before any of it is written.
package hfsplus

import (
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/deploymenttheory/go-apfs-v2/internal/decmpfs"
)

// validateTree refuses a tree this writer cannot represent faithfully, before
// anything is written.
//
// The APFS writer has had this since it learned to carry compression; HFS+ had
// none at all, so a hand-built Entry with a com.apple.decmpfs attribute was
// written with the compression flag clear — a file that claims compressed
// content in its attribute and denies it in its mode. The walk never produced
// one, which is why it went unnoticed.
func validateTree(root *Entry) error {
	return walkEntries(root, ".", func(e *Entry, path string) error {
		return validateEntry(e, path)
	})
}

// walkEntries visits every entry in the tree, giving each its path for error
// messages.
func walkEntries(e *Entry, path string, visit func(*Entry, string) error) error {
	if err := visit(e, path); err != nil {
		return err
	}
	for _, child := range e.Children {
		childPath := child.Name
		if path != "." {
			childPath = path + "/" + child.Name
		}
		if err := walkEntries(child, childPath, visit); err != nil {
			return err
		}
	}
	return nil
}

func validateEntry(e *Entry, path string) error {
	if err := validateFinderInfo(e); err != nil {
		return err
	}
	for name := range e.Xattrs {
		if !utf8.ValidString(name) {
			return fmt.Errorf("hfsplus: invalid UTF-8 attribute name on %q", path)
		}
		if name == "" {
			return fmt.Errorf("hfsplus: %q has an extended attribute with an empty name", path)
		}
		if strings.ContainsRune(name, 0) {
			return fmt.Errorf("hfsplus: extended attribute name %q on %q contains a NUL", name, path)
		}
		if name == decmpfs.ResourceForkName {
			return fmt.Errorf("hfsplus: %q carries %s as an extended attribute; on HFS+ a resource fork is a fork of the catalog record, so it belongs in Entry.ResourceFork",
				path, decmpfs.ResourceForkName)
		}
	}

	if err := validateContent(e, path); err != nil {
		return err
	}

	_, compressed := compressedValue(e)
	if !compressed {
		return nil
	}
	// A compressed file's content is the attribute, and for the fork-based
	// types the resource fork alongside it. HFS+ keeps that fork on the
	// catalog record rather than in the attributes file, so it is passed from
	// there.
	if err := validateCompressedValue(e); err != nil {
		return fmt.Errorf("hfsplus: %q: %w", path, err)
	}
	if e.Mode.IsDir() || e.Mode&os.ModeSymlink != 0 {
		return fmt.Errorf("hfsplus: %q carries %s but is not a regular file", path, decmpfs.AttributeName)
	}
	return nil
}

// validateContent refuses an entry whose content is described two ways, or in a
// way the layout cannot rely on.
//
// Everything about where a file lands is decided from its length before a byte
// of it is read, so a lazily supplied file has to say how long it is, and an
// entry that names both sources has no single answer.
func validateContent(e *Entry, path string) error {
	if e.Open == nil {
		if e.Size != 0 {
			return fmt.Errorf("hfsplus: %q sets Size without Open; an entry holding its content in Data takes its length from there", path)
		}
		return nil
	}
	if len(e.Data) > 0 {
		return fmt.Errorf("hfsplus: %q supplies its content through both Data and Open", path)
	}
	if e.Mode.IsDir() || e.Mode&os.ModeSymlink != 0 {
		return fmt.Errorf("hfsplus: %q supplies content through Open but is not a regular file", path)
	}
	if e.Size < 0 || int64(int(e.Size)) != e.Size {
		return fmt.Errorf("hfsplus: %q declares a Size of %d, which no data fork can have", path, e.Size)
	}
	return nil
}
