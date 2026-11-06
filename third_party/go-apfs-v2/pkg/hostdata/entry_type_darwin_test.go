package hostdata

import (
	"errors"
	"os"
	"testing"
)

func TestEntryTypeDarwinDecode(t *testing.T) {
	for native, want := range map[uint32]os.FileMode{1: 0, 2: os.ModeDir, 3: os.ModeDevice, 4: os.ModeDevice | os.ModeCharDevice, 5: os.ModeSymlink, 6: os.ModeSocket, 7: os.ModeNamedPipe} {
		got, err := decodeEntryType([2]uint32{8, native})
		if err != nil || got != want {
			t.Fatal(native, got, err)
		}
	}
	for _, data := range [][2]uint32{{0, 1}, {4, 1}, {12, 1}} {
		if _, err := decodeEntryType(data); !errors.Is(err, os.ErrInvalid) {
			t.Fatal(data, err)
		}
	}
	if _, err := decodeEntryType([2]uint32{8, 0}); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal(err)
	}
}

func TestEntryTypeDarwinDescriptorErrors(t *testing.T) {
	if _, err := entryTypeAt(nil, "file"); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	parent, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entryTypeAt(parent, "bad\x00name"); err == nil {
		t.Fatal("accepted NUL")
	}
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := entryTypeAt(parent, "file"); err == nil {
		t.Fatal("accepted closed parent")
	}
}
