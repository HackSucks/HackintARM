package nameunicode

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestCompleteNativeScalarAdmission(t *testing.T) {
	for _, major := range []int{15, 26, 27} {
		t.Run(fmt.Sprint(major), func(t *testing.T) {
			p := filepath.Join("..", "..", fmt.Sprintf("testdata/appledouble/native/name-admission-macos%d.json.gz", major))
			f, e := os.Open(p)
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			z, e := gzip.NewReader(f)
			if e != nil {
				t.Fatal(e)
			}
			defer z.Close()
			var c struct {
				Schema  int
				Volumes []struct {
					Kind    string
					Results []byte
				}
			}
			if e = json.NewDecoder(z).Decode(&c); e != nil {
				t.Fatal(e)
			}
			if c.Schema != 1 || len(c.Volumes) != 2 {
				t.Fatal("native admission inventory")
			}
			for i, v := range c.Volumes {
				if v.Kind != []string{"APFS", "APFSX"}[i] || len(v.Results) != 0x110000 {
					t.Fatal("native scalar inventory")
				}
				count := 0
				for scalar, errno := range v.Results {
					want := errno == 0
					if got := APFSCreateAllowed(rune(scalar), major); got != want {
						t.Fatalf("%s U+%04X got%v nativeerrno%d", v.Kind, scalar, got, errno)
					}
					if errno != 255 {
						count++
					}
				}
				if count != 1112062 {
					t.Fatal(count)
				}
			}
		})
	}
	for _, major := range []int{0, 14, 16, 28} {
		if APFSCreateAllowed('A', major) {
			t.Fatal("unqualified profile")
		}
	}
	for _, r := range []rune{-1, 0x110000} {
		if APFSCreateAllowed(r, 27) {
			t.Fatal("outside scalar domain")
		}
	}
}
