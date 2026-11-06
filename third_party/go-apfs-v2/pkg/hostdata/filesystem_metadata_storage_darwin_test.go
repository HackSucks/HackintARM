package hostdata

import (
	"errors"
	"os"
	"testing"
)

func TestFilesystemMetadataStorageCapabilities(t *testing.T) {
	for _, tc := range []struct {
		length, value, valid uint32
		want, failure        bool
	}{
		{36, 0x4000, 0x4000, false, false},
		{36, 0, 0x4000, true, false},
		{36, 0, 0, true, false},
		{36, 0x4000, 0, true, false},
		{0, 0x4000, 0x4000, false, true},
		{40, 0, 0, false, true},
	} {
		got, err := filesystemXattrStorageResult(tc.length, tc.value, tc.valid)
		if got != tc.want || (err != nil) != tc.failure || err != nil && !errors.Is(err, os.ErrInvalid) {
			t.Fatal(tc, got, err)
		}
	}
}
