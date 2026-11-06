package hostdata_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/securitycopy"
)

func TestNativeSecurityCopyVolume(t *testing.T) {
	b, e := os.ReadFile("../../testdata/appledouble/native/security-copy-volume.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	z, e := gzip.NewReader(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var f securitycopy.Fixture
	if e = json.NewDecoder(z).Decode(&f); e != nil {
		t.Fatal(e)
	}
	helper, e := os.ReadFile("../../testdata/appledouble/native/security-copy-volume.c")
	if e != nil {
		t.Fatal(e)
	}
	helper = bytes.ReplaceAll(helper, []byte("\r\n"), []byte("\n"))
	if f.HelperSHA256 != fmt.Sprintf("%x", sha256.Sum256(helper)) || f.CopyfileSHA256 != "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c" || f.LibcSHA256 != "31c8a6c3729759582796700827583b17639ed0324f44dafb4927f1332bc040ff" {
		t.Fatal("source/helper provenance")
	}
	if len(f.Models) != 3888 || len(f.Applications) != 288 {
		t.Fatalf("required corpus missing cases: %d/%d", len(f.Models), len(f.Applications))
	}
	if len(f.Helpers) != 1 {
		t.Fatal("missing shared helper provenance")
	}
	for path, want := range f.Helpers {
		b, err := os.ReadFile("../../" + path)
		if err != nil {
			t.Fatal(err)
		}
		b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
		if fmt.Sprintf("%x", sha256.Sum256(b)) != want {
			t.Fatal("shared helper provenance", path)
		}
	}
	for _, cases := range [][]securitycopy.Case{f.Models, f.Applications} {
		for _, tc := range cases {
			t.Run(tc.Name, func(t *testing.T) {
				result, _, err := securitycopy.Replay(tc)
				if err != nil {
					t.Fatal(err)
				}
				if tc.Kind != "" {
					n := tc.Native
					if !n.IdentityUnchanged || !n.PayloadUnchanged || n.Filesystem != "apfs" || !reflect.DeepEqual(n.SourceBefore, n.SourceAfter) {
						t.Fatal("native preservation")
					}
					if !result.Completed {
						t.Fatal("native stage completion")
					}
				}
			})
		}
	}
}
