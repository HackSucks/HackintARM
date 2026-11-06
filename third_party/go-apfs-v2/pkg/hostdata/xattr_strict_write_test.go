//go:build darwin || linux || windows

package hostdata

import (
	"errors"
	"os"
	"testing"
)

func TestStrictXattrWriteValidation(t *testing.T) {
	for _, name := range []string{"", "bad\x00name", "user.valid"} {
		if err := SetXattr(nil, name, nil); !errors.Is(err, os.ErrInvalid) {
			t.Fatal(name, err)
		}
	}
	f, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := SetXattr(f, "user.valid", []byte{1}); err == nil {
		t.Fatal(err)
	}
}
