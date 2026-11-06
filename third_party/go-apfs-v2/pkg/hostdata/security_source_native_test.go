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

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/securitysource"
)

func TestNativeSecuritySource(t *testing.T) {
	b, e := os.ReadFile("../../testdata/appledouble/native/security-source.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	z, e := gzip.NewReader(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var fixture securitysource.Fixture
	if e = json.NewDecoder(z).Decode(&fixture); e != nil {
		t.Fatal(e)
	}
	if len(fixture.Models) != 2160 || len(fixture.Applications) != 108 {
		t.Fatal("incomplete corpus")
	}
	for name, want := range map[string]string{"security-source.c": fixture.HelperSHA256, "security-copy.c": fixture.ParentSHA256} {
		b, e := os.ReadFile("../../testdata/appledouble/native/" + name)
		if e != nil {
			t.Fatal(e)
		}
		b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
		if fmt.Sprintf("%x", sha256.Sum256(b)) != want {
			t.Fatal("helper provenance", name)
		}
	}
	if fixture.CopyfileSHA256 != "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c" || fixture.LibcSHA256 != "31c8a6c3729759582796700827583b17639ed0324f44dafb4927f1332bc040ff" {
		t.Fatal("Apple source provenance")
	}
	for _, cases := range [][]securitysource.Case{fixture.Models, fixture.Applications} {
		for _, tc := range cases {
			t.Run(tc.Name, func(t *testing.T) {
				result, _, err := securitysource.Replay(tc)
				if err != nil {
					t.Fatal(err)
				}
				if tc.Kind != "" {
					n := tc.Native
					if !result.Capture.Completed || !n.IdentityUnchanged || !n.PayloadUnchanged || !reflect.DeepEqual(n.SourceBefore, n.SourceAfter) {
						t.Fatal("native preservation")
					}
					if n.PayloadPermissionCleanups != 0 && tc.Kind != "symlink" {
						t.Fatal("unexpected permission cleanup")
					}
				}
			})
		}
	}
}
