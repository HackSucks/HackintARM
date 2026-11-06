//go:build !darwin

package hostdata

import (
	"context"
	"errors"
	"testing"

	heldfixture "github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"
)

func TestAppleDoubleObjectForeignAcquisition(t *testing.T) {
	file := heldfixture.Source(t, 0600)
	if _, err := NewHostAppleDoubleObject(context.Background(), file); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := newHostObjectAttributes(file); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal(err)
	}
}
