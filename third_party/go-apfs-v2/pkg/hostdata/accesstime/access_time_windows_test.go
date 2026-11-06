package accesstime

import (
	"errors"
	"os"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"
)

type zeroAccessFileInfo struct{ os.FileInfo }

func (i zeroAccessFileInfo) Sys() any {
	s := *i.FileInfo.Sys().(*syscall.Win32FileAttributeData)
	s.LastAccessTime = syscall.Filetime{}
	return &s
}

func TestCarrierWindowsAccessTimeSentinel(t *testing.T) {
	file := heldfixture.Source(t, 0600)
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := copyAccessTime(file, zeroAccessFileInfo{info}); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("zero access sentinel: %v", err)
	}
}
