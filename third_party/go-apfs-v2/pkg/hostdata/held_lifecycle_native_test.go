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

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldlifecycle"
)

func TestHeldLifecycleNative(t *testing.T) {
	f, err := os.Open("../../testdata/appledouble/native/held-lifecycle.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var fixture heldlifecycle.Fixture
	if err = json.NewDecoder(z).Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	helper, err := os.ReadFile("../../testdata/appledouble/native/held-lifecycle.c")
	if err != nil {
		t.Fatal(err)
	}
	helper = bytes.ReplaceAll(helper, []byte("\r\n"), []byte("\n"))
	if fmt.Sprintf("%x", sha256.Sum256(helper)) != fixture.HelperSHA256 || fixture.SourceSHA256 != "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c" {
		t.Fatal("native source provenance")
	}
	cases := heldlifecycle.Cases()
	if len(fixture.Cases) != 1140 || len(cases) != len(fixture.Cases) {
		t.Fatal("native lifecycle cases missing", len(cases), len(fixture.Cases))
	}
	for i, c := range fixture.Cases {
		t.Run(fmt.Sprintf("%04d", i), func(t *testing.T) {
			spec := c
			spec.Native = heldlifecycle.Observation{}
			if !reflect.DeepEqual(spec, cases[i]) {
				t.Fatal("native input changed")
			}
			if err := heldlifecycle.Replay(c); err != nil {
				t.Fatal(err)
			}
		})
	}
}
