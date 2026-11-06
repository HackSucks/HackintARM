package recompression

import (
	"path"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/authorization"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

// lookupPathComponent compares captured siblings only after their parent has
// passed Search. Comparison is distinct from creation admission: a filesystem
// may reject creating a character while ordinary lookup reports ENOENT.
func lookupPathComponent(records map[string]metatransport.Record, parent, component string, mount *authorization.Mount) (string, metatransport.Record, bool, error) {
	if mount == nil || mount.CaseSensitive == nil {
		return "", metatransport.Record{}, false, ErrAuthority
	}
	var compare func(string, string) int
	switch mount.Filesystem {
	case "apfs":
		if err := apfs.ValidateLookupName(component); err != nil {
			return "", metatransport.Record{}, false, err
		}
		compare = func(a, b string) int { return apfs.CompareNamesWithUTF8([]byte(a), []byte(b), !*mount.CaseSensitive) }
	case "hfs":
		if err := hfsplus.ValidateLookupName(component); err != nil {
			return "", metatransport.Record{}, false, err
		}
		compare = func(a, b string) int { return hfsplus.CompareNames(a, b, *mount.CaseSensitive) }
	default:
		return "", metatransport.Record{}, false, ErrAuthority
	}
	var selected string
	var record metatransport.Record
	found := false
	for name, candidate := range records {
		if name == parent || path.Dir(name) != parent || compare(path.Base(name), component) != 0 {
			continue
		}
		if found {
			// Even an exact spelling must not hide an impossible pair of names
			// on the captured volume or select a record by map iteration order.
			return "", metatransport.Record{}, false, metatransport.ErrConflict
		}
		selected, record, found = name, candidate, true
	}
	return selected, record, found, nil
}
