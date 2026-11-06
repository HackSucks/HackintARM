package unixmode

import (
	"io/fs"
	"testing"
)

func TestImageModePermissions(t *testing.T) {
	for raw := uint16(0); raw <= 07777; raw++ {
		// Construct independently of the inverse under test.
		mode := fs.FileMode(raw & 0777)
		if raw&04000 != 0 {
			mode |= fs.ModeSetuid
		}
		if raw&02000 != 0 {
			mode |= fs.ModeSetgid
		}
		if raw&01000 != 0 {
			mode |= fs.ModeSticky
		}
		for _, kind := range []fs.FileMode{0, fs.ModeDir, fs.ModeSymlink, fs.ModeDevice, fs.ModeNamedPipe} {
			if got := Permissions(mode|kind, 0755, true); got != raw {
				t.Fatalf("explicit %#o/%s: %#o", raw, kind, got)
			}
		}
		for _, kind := range []uint16{0, 0100000, 0040000, 0120000, 0060000} {
			if got := FilePermissions(raw | kind); got != mode {
				t.Fatalf("read %#o: %s != %s", raw|kind, got, mode)
			}
		}
		for _, fallback := range []uint16{0644, 0755} {
			want := raw
			if raw&0777 == 0 {
				want |= fallback
			}
			if got := Permissions(mode, fallback, false); got != want {
				t.Fatalf("default %#o: %#o != %#o", raw, got, want)
			}
		}
	}
}
