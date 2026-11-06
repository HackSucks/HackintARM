package bsdflags

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"
)

func TestImageFlagsSelection(t *testing.T) {
	for _, hfs := range []bool{false, true} {
		for _, compressed := range []bool{false, true} {
			want := uint32(0)
			if compressed {
				want = Compressed
			}
			got, e := Select(nil, compressed, hfs)
			if e != nil || got != want {
				t.Fatal(got, e)
			}
			for _, flags := range []uint32{0, 1, 2, 4, 8, 0x20, 0x40, 0x80, 0x8000, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x00ff80ff, 0x100, 0x10000000, 0xffffffff} {
				t.Run(fmt.Sprintf("hfs%t-c%t-%x", hfs, compressed, flags), func(t *testing.T) {
					before := flags
					got, e := Select(&flags, compressed, hfs)
					valid := (flags&Compressed == 0 || compressed) && (!hfs || flags&^0x00ff80ff == 0)
					if valid {
						if e != nil || got != flags {
							t.Fatal(got, e)
						}
					} else if !errors.Is(e, fs.ErrInvalid) || got != 0 {
						t.Fatal(got, e)
					}
					if flags != before {
						t.Fatal("input changed")
					}
				})
			}
		}
	}
}
func TestImageFlagsHFSCatalogNormalization(t *testing.T) {
	for _, tc := range []struct {
		name         string
		owner, admin uint8
		mode         uint16
		dir, locked  bool
		finder       uint16
		want         uint32
	}{
		{"bytes", 0x81, 0x19, 0100644, false, false, 0, 0x190081},
		{"locked-implied", 0, 0, 0100644, false, true, 0, 2},
		{"locked-user", 2, 0, 0100644, false, true, 0, 2},
		{"locked-system", 0, 2, 0100644, false, true, 0, 0x20000},
		{"unlocked-both", 2, 2, 0100644, false, false, 0, 0},
		{"directory", 2, 2, 040755, true, false, 0x4000, 0x28002},
		{"legacy-file", 255, 255, 0, false, false, 0x4000, 0x8000},
		{"legacy-locked", 255, 255, 0, false, true, 0, 2},
		{"legacy-directory", 255, 255, 0, true, false, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := HFS(tc.owner, tc.admin, tc.mode, tc.dir, tc.locked, tc.finder); got != tc.want {
				t.Fatalf("%x != %x", got, tc.want)
			}
		})
	}
}
