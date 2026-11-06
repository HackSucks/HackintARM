package captureprovenance

import (
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/nativeevidence"
)

func TestRetainedNativeCatalogIntegrity(t *testing.T) {
	source := os.DirFS("../../..")
	catalog, err := nativeevidence.ReadCatalog(source, retainedCatalog)
	if err != nil {
		t.Fatal(err)
	}
	if err = nativeevidence.VerifyRetainedCatalog(t.Context(), source, catalog); err != nil {
		t.Fatal(err)
	}
}
