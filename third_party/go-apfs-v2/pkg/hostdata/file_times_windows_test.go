package hostdata

import (
	"errors"
	"os"
	"testing"
	"time"

	heldfixture "github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"
	"golang.org/x/sys/windows"
)

func openTimeTestFile(name string, _ bool) (*os.File, error) {
	h, err := openXattrPath(name, windows.FILE_WRITE_ATTRIBUTES|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), name), nil
}

func TestCarrierWindowsTimePrecision(t *testing.T) {
	file := heldfixture.Source(t, 0600)
	when := time.Unix(946684800, 0)
	for _, tc := range [][2]time.Time{{when.Add(time.Nanosecond), when}, {when, when.Add(time.Nanosecond)}} {
		if err := SetFileTimes(file, tc[0], tc[1]); !errors.Is(err, os.ErrInvalid) {
			t.Fatalf("precision: %v", err)
		}
	}
}
