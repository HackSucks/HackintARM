package hfsplus

import (
	"fmt"
	"sort"
	"syscall"
)

// validateCreationNames checks ordinary entries before layout or source reads.
// The volume label has its own catalog contract. HFS conversion is frozen and
// independent of the receiving host's Unicode version.
func validateCreationNames(root *Entry, caseSensitive bool) error {
	active := map[*Entry]bool{}
	var walk func(*Entry, bool) error
	walk = func(parent *Entry, represented bool) error {
		if parent == nil {
			return fmt.Errorf("hfsplus: nil directory entry: %w", syscall.EINVAL)
		}
		if active[parent] {
			return fmt.Errorf("hfsplus: cyclic directory tree: %w", syscall.EINVAL)
		}
		active[parent] = true
		defer delete(active, parent)
		names := make([]string, 0, len(parent.Children))
		for _, child := range parent.Children {
			if child == nil {
				return fmt.Errorf("hfsplus: nil child entry: %w", syscall.EINVAL)
			}
			if represented {
				if child.Name == "." || child.Name == ".." {
					return fmt.Errorf("hfsplus: reserved component %q: %w", child.Name, syscall.EEXIST)
				}
				if _, err := NormalizeLookupName(child.Name); err != nil {
					return fmt.Errorf("hfsplus: entry %q: %w", child.Name, err)
				}
				names = append(names, child.Name)
			}
			// Value preparation visits every node, including unwritten file children;
			// detect invalid graphs there without imposing names on unrepresented nodes.
			if err := walk(child, represented && child.Mode.IsDir()); err != nil {
				return err
			}
		}
		sort.Slice(names, func(i, j int) bool { return CompareNames(names[i], names[j], caseSensitive) < 0 })
		for i := 1; i < len(names); i++ {
			if CompareNames(names[i-1], names[i], caseSensitive) == 0 {
				return fmt.Errorf("hfsplus: names %q and %q identify the same native entry: %w", names[i-1], names[i], syscall.EEXIST)
			}
		}
		return nil
	}
	return walk(root, true)
}
