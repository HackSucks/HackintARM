//go:build !darwin

package hostdata

import (
	"errors"
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/decmpfs"
)

func TestCommitHeldCompressionRequiresNativeDarwinView(t *testing.T) {
	f, e := os.CreateTemp(t.TempDir(), "native-view-")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if _, e = CommitHeldCompression(t.Context(), f, decmpfs.EncodedFile{}, StatCopySource{}); !errors.Is(e, errors.ErrUnsupported) {
		t.Fatal(e)
	}
}

func TestInstallHeldCompressionRequiresNativeDarwinView(t *testing.T) {
	f, e := os.CreateTemp(t.TempDir(), "native-install-")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if _, e = InstallHeldCompression(t.Context(), f, decmpfs.EncodedFile{}, nil, StatCopySource{}); !errors.Is(e, errors.ErrUnsupported) {
		t.Fatal(e)
	}
}
