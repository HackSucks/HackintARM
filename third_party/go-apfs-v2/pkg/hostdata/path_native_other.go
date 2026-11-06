//go:build !darwin

package hostdata

import (
	"errors"
	"os"

	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

// Native Darwin path primitives have no receiving-host substitute. Captured
// path providers execute the same Go policy using preserved logical metadata.
func CapturePathMetadata(string, bool) (PathMetadata, error) {
	return PathMetadata{}, errors.ErrUnsupported
}
func WritePathSecurity(string, aclmeta.DarwinChmodProperties) error { return errors.ErrUnsupported }
func PathProtectionSupport(string) (bool, error)                    { return false, errors.ErrUnsupported }
func FileProtectionSupport(*os.File) (bool, error)                  { return false, errors.ErrUnsupported }
func ReadProtectionClass(*os.File) (int, error)                     { return 0, errors.ErrUnsupported }
func SetProtectionClass(*os.File, int) error                        { return errors.ErrUnsupported }
func OpenProtectedPath(string, int, int, uint32) (*os.File, error)  { return nil, errors.ErrUnsupported }
