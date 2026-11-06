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

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/statcopy"
)

func TestNativeStatCopy(t *testing.T) {
	b, e := os.ReadFile("../../testdata/appledouble/native/stat-copy.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	z, e := gzip.NewReader(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var f statcopy.Fixture
	if e = json.NewDecoder(z).Decode(&f); e != nil {
		t.Fatal(e)
	}
	helper, e := os.ReadFile("../../testdata/appledouble/native/stat-copy.c")
	if e != nil {
		t.Fatal(e)
	}
	helper = bytes.ReplaceAll(helper, []byte("\r\n"), []byte("\n"))
	if f.HelperSHA256 != fmt.Sprintf("%x", sha256.Sum256(helper)) || f.CopyfileSHA256 != "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c" || f.PrivateSHA256 != "8ac427e2c1dbe0ca92cfe2fbf114df90fd747f3fbe25c2a4919ff941a1be81c5" || f.FSCTLSHA256 != "dae81f19610f25fb7905b5c725f728fec4b8b4978f6214374415d420ffac258d" {
		t.Fatal("native source/helper provenance")
	}
	if len(f.Models) != 1031 || len(f.Applications) != 192 {
		t.Fatalf("incomplete corpus: %d/%d", len(f.Models), len(f.Applications))
	}
	seen := map[string]bool{}
	for _, cases := range [][]statcopy.Case{f.Models, f.Applications} {
		for _, tc := range cases {
			if seen[tc.Name] {
				t.Fatal("duplicate case", tc.Name)
			}
			seen[tc.Name] = true
			t.Run(tc.Name, func(t *testing.T) {
				if _, _, e := statcopy.Replay(tc); e != nil {
					t.Fatal(e)
				}
				if tc.Kind != "" {
					n := tc.Native
					if !n.IdentityUnchanged || !n.PayloadUnchanged || n.Filesystem != "apfs" || !reflect.DeepEqual(n.SourceBefore, n.SourceAfter) || n.Before.ACL != n.After.ACL || n.Before.Xattr != n.After.Xattr {
						t.Fatal("native preservation")
					}
				}
			})
		}
	}
}
