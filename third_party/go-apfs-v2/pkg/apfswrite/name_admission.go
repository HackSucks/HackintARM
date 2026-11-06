package apfswrite

import (
	"fmt"
	"github.com/deploymenttheory/go-apfs-v2/internal/nameunicode"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
	"syscall"
)

// validateCreationNames runs before any image bytes are written. Volume labels
// and snapshot names have separate native contracts and keep their own checks.
func validateCreationNames(target osversion.Version, volumes []VolumeSpec) error {
	if target == (osversion.Version{}) {
		target = osversion.Version{Major: 27}
	}
	if _, err := osversion.ProfileForMacOS(target); err != nil {
		return err
	}
	for _, volume := range volumes {
		var children []*Entry
		if volume.Root != nil {
			children = append(children, volume.Root.Children...)
		}
		for _, file := range volume.RootFiles {
			children = append(children, &Entry{Name: file.Name})
		}
		active := map[*Entry]bool{}
		var walk func([]*Entry) error
		walk = func(entries []*Entry) error {
			names := map[string]string{}
			for _, entry := range entries {
				if entry == nil {
					return fmt.Errorf("apfswrite: nil directory entry: %w", syscall.EINVAL)
				}
				if active[entry] {
					return fmt.Errorf("apfswrite: cyclic directory tree: %w", syscall.EINVAL)
				}
				if err := apfs.ValidateCreateName(entry.Name, target); err != nil {
					return fmt.Errorf("apfswrite: name %q: %w", entry.Name, err)
				}
				key := string(nameunicode.APFS(entry.Name, !volume.CaseSensitive))
				if other, exists := names[key]; exists {
					return fmt.Errorf("apfswrite: names %q and %q identify the same native entry: %w", other, entry.Name, syscall.EEXIST)
				}
				names[key] = entry.Name
				if entry.isDirEntry() {
					active[entry] = true
					if err := walk(entry.Children); err != nil {
						return err
					}
					delete(active, entry)
				}
			}
			return nil
		}
		if err := walk(children); err != nil {
			return err
		}
	}
	return nil
}
