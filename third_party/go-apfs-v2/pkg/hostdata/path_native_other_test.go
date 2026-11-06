//go:build !darwin

package hostdata

import (
	"errors"
	"testing"

	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

func TestPathNativeForeignAcquisition(t *testing.T) {
	_, capture := CapturePathMetadata("file", false)
	_, path := PathProtectionSupport("file")
	_, file := FileProtectionSupport(nil)
	_, read := ReadProtectionClass(nil)
	_, open := OpenProtectedPath("file", 0, 0, 0600)
	for _, err := range []error{capture, path, file, read, open, WritePathSecurity("file", aclmeta.DarwinChmodProperties{}), SetProtectionClass(nil, 0)} {
		if !errors.Is(err, errors.ErrUnsupported) {
			t.Fatal(err)
		}
	}
}
