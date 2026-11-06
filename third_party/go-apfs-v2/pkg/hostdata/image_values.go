package hostdata

import "github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"

// ImageXattrValuesFS exposes borrowed, sized extended-attribute readers. The
// image must remain open and immutable for every subsequent read. Enumerating
// values does not materialize large attributes or resource forks. Errors must
// not be treated as an empty namespace or a partial successful capture.
type ImageXattrValuesFS interface {
	XattrValues(name string) (map[string]appledouble.Value, error)
}
