package hostdata_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/xattrrestore"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func TestXattrRestoreNative(t *testing.T) {
	data, e := os.ReadFile("../../testdata/appledouble/native/xattr-restore.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	z, e := gzip.NewReader(bytes.NewReader(data))
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var f xattrrestore.Fixture
	if e = json.NewDecoder(z).Decode(&f); e != nil {
		t.Fatal(e)
	}
	helper, e := os.ReadFile("../../testdata/appledouble/native/xattr-restore.c")
	if e != nil {
		t.Fatal(e)
	}
	helper = bytes.ReplaceAll(helper, []byte("\r\n"), []byte("\n"))
	if f.HelperSHA256 != fmt.Sprintf("%x", sha256.Sum256(helper)) || f.CopyfileSHA256 != "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c" || f.PolicySHA256 != "991a340ad26bf9086f9fcbca8eafb0dee4c2ab38e41d152c60fa218e5d4226dc" || f.HeaderSHA256 != "0fd2d35d0ae3efba30d30b8c470dae4bc42972455c6d8d5246fec44732f43d49" {
		t.Fatal("source provenance")
	}
	for _, set := range []struct {
		cases, want []xattrrestore.Case
		live        bool
	}{{f.Cases, xattrrestore.Cases(), false}, {f.Live, xattrrestore.LiveCases(), true}} {
		if len(set.cases) != len(set.want) || len(set.cases) == 0 {
			t.Fatal("incomplete corpus")
		}
		for i, c := range set.cases {
			selection := c
			selection.Native = xattrrestore.Observation{}
			if !reflect.DeepEqual(selection, set.want[i]) {
				t.Fatal("changed scenario", c.Name)
			}
			t.Run(c.Name, func(t *testing.T) {
				if e := xattrrestore.Replay(c, set.live); e != nil {
					t.Fatal(e)
				}
			})
		}
	}
}
func TestXattrRestoreInputsAndOwnership(t *testing.T) {
	for _, name := range []string{"", "bad\x00name", appledouble.ACLTextName, appledouble.QuarantineName} {
		r, e := hostdata.RestoreXattr(name, nil, hostdata.XattrRestoreOptions{}, func(string, []byte) error { t.Fatal("write on invalid name"); return nil })
		if !errors.Is(e, os.ErrInvalid) || r.Completed || r.Applied {
			t.Fatal(r, e)
		}
	}
	r, e := hostdata.RestoreXattr("ordinary", nil, hostdata.XattrRestoreOptions{}, nil)
	if !errors.Is(e, os.ErrInvalid) || !r.Selected {
		t.Fatal(r, e)
	}
	r, e = hostdata.RestoreXattr("ordinary#N", nil, hostdata.XattrRestoreOptions{}, nil)
	if e != nil || !r.Completed || r.Selected {
		t.Fatal(r, e)
	}
	value := []byte{1, 2, 3}
	options := hostdata.XattrRestoreOptions{Callback: func(n hostdata.XattrRestoreNotice) hostdata.CopyPipelineAction {
		if n.Event == hostdata.XattrRestoreStart {
			value[0] = 9
		}
		return hostdata.CopyPipelineContinue
	}}
	r, e = hostdata.RestoreXattr("ordinary", value, options, func(_ string, owned []byte) error {
		if !bytes.Equal(owned, []byte{1, 2, 3}) {
			t.Fatal("source not frozen", owned)
		}
		owned[1] = 8
		return nil
	})
	if e != nil || !r.Applied || !r.Completed || r.Copied != 3 || !bytes.Equal(value, []byte{9, 2, 3}) {
		t.Fatal(r, e, value)
	}
	cause := errors.New("underlying EPERM")
	options.Callback = func(n hostdata.XattrRestoreNotice) hostdata.CopyPipelineAction {
		if n.Event == hostdata.XattrRestoreFinish && !errors.Is(n.WriteError, cause) {
			t.Fatal("missing suppressed cause")
		}
		return hostdata.CopyPipelineContinue
	}
	r, e = hostdata.RestoreXattr("com.apple.root.installed", nil, options, func(string, []byte) error { return errors.Join(hostdata.ErrXattrRestoreNotPermitted, cause) })
	if e != nil || r.Applied || !r.Completed || !errors.Is(r.WriteError, cause) {
		t.Fatal(r, e)
	}
}
