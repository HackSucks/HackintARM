package hostdata_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/unpackrestore"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func TestUnpackRestoreNative(t *testing.T) {
	for _, name := range []string{"unpack-restore.json.gz", "unpack-restore-ci.json.gz"} {
		t.Run(name, func(t *testing.T) {
			z, e := os.Open("../../testdata/appledouble/native/" + name)
			if e != nil {
				t.Fatal(e)
			}
			defer z.Close()
			g, e := gzip.NewReader(z)
			if e != nil {
				t.Fatal(e)
			}
			defer g.Close()
			var f unpackrestore.Fixture
			if e = json.NewDecoder(g).Decode(&f); e != nil {
				t.Fatal(e)
			}
			b, e := os.ReadFile("../../testdata/appledouble/native/unpack-restore.c")
			if e != nil {
				t.Fatal(e)
			}
			// Git may check the qualification helper out with CRLF on Windows.
			b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
			if fmt.Sprintf("%x", sha256.Sum256(b)) != f.HelperSHA256 || f.CopyfileSHA256 != "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c" || f.PolicySHA256 != "991a340ad26bf9086f9fcbca8eafb0dee4c2ab38e41d152c60fa218e5d4226dc" || f.HeaderSHA256 != "0fd2d35d0ae3efba30d30b8c470dae4bc42972455c6d8d5246fec44732f43d49" {
				t.Fatal("source provenance")
			}
			if !reflect.DeepEqual(f.Images, unpackrestore.Images()) {
				t.Fatal("image inputs changed")
			}
			for name, set := range map[string]struct{ actual, want []unpackrestore.Case }{"model": {f.Cases, unpackrestore.Cases()}, "live": {f.Live, unpackrestore.LiveCases()}} {
				if len(set.actual) != len(set.want) {
					t.Fatal("missing cases")
				}
				for i, c := range set.actual {
					if name == "live" {
						writes := 0
						for _, event := range c.Native.Events {
							if (event.Kind == "ordinary" || event.Kind == "finder-info" || event.Kind == "resource-fork") && event.Code == 0 {
								writes++
							}
						}
						if !c.Native.RemovedSeeds || c.Native.VerifiedWrites != writes {
							t.Fatal("missing native readback/removal evidence")
						}
					}
					spec := c
					spec.Native = unpackrestore.Observation{}
					if !reflect.DeepEqual(spec, set.want[i]) {
						t.Fatalf("changed %s input %d", name, i)
					}
					t.Run(fmt.Sprintf("%s-%04d", name, i), func(t *testing.T) {
						if e := unpackrestore.Replay(c, f.Images); e != nil {
							t.Fatal(e)
						}
					})
				}
			}
		})
	}
}

type unpackEdgeBackend struct {
	hostdata.UnpackBackend
	size              int
	names             []string
	sizeErr, namesErr error
	calls             []string
	writes            map[string][]byte
	result            hostdata.CopyStageResult
	mutate            func(string, []byte)
}

func (b *unpackEdgeBackend) ListXattrSize() (int, error) {
	b.calls = append(b.calls, "size")
	return b.size, b.sizeErr
}
func (b *unpackEdgeBackend) XattrNames(int) ([]string, error) {
	b.calls = append(b.calls, "names")
	return b.names, b.namesErr
}
func (b *unpackEdgeBackend) RemoveXattr(n string) error {
	b.calls = append(b.calls, "remove:"+n)
	return nil
}
func (b *unpackEdgeBackend) WriteXattr(n string, v []byte) error {
	if b.writes == nil {
		b.writes = map[string][]byte{}
	}
	b.writes[n] = bytes.Clone(v)
	if b.mutate != nil {
		b.mutate(n, v)
	}
	return nil
}
func (b *unpackEdgeBackend) ACL([]byte) hostdata.CopyStageResult { return b.result }
func (b *unpackEdgeBackend) Stat(bool) hostdata.CopyStageResult  { return b.result }
func unpackData(t *testing.T, f appledouble.File) []byte {
	t.Helper()
	b, e := f.Encode()
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestUnpackRestoreValidationAndDiagnostics(t *testing.T) {
	data := unpackData(t, appledouble.File{})
	b := &unpackEdgeBackend{}
	if r, e := hostdata.RestoreAppleDouble(data, hostdata.UnpackOptions{}, nil); !errors.Is(e, os.ErrInvalid) || r.Code != -1 {
		t.Fatal(r, e)
	}
	if r, e := hostdata.RestoreAppleDouble([]byte("bad"), hostdata.UnpackOptions{}, b); e == nil || r.Code != -1 || len(b.calls) != 0 {
		t.Fatal(r, e, b.calls)
	}
	for _, tc := range []struct {
		size  int
		names []string
	}{{-1, nil}, {3, []string{"valid", "bad\x00name"}}, {3, []string{""}}} {
		b = &unpackEdgeBackend{size: tc.size, names: tc.names}
		r, e := hostdata.RestoreAppleDouble(data, hostdata.UnpackOptions{}, b)
		if !errors.Is(e, os.ErrInvalid) || r.Code != -1 || strings.Contains(strings.Join(b.calls, ","), "remove:") {
			t.Fatal(r, e, b.calls)
		}
	}
	failure := errors.New("list failed")
	b = &unpackEdgeBackend{sizeErr: failure}
	r, e := hostdata.RestoreAppleDouble(data, hostdata.UnpackOptions{}, b)
	if e != nil || r.Code != 0 || r.ReachedEnd || len(r.Failures) != 1 || !errors.Is(r.Failures[0].Err, failure) {
		t.Fatal(r, e)
	}
	b = &unpackEdgeBackend{result: hostdata.CopyStageResult{Code: 7}}
	r, e = hostdata.RestoreAppleDouble(data, hostdata.UnpackOptions{Stat: true}, b)
	if e == nil || r.Code != 7 || !r.ReachedEnd {
		t.Fatal(r, e)
	}
	b = &unpackEdgeBackend{result: hostdata.CopyStageResult{Err: failure}}
	r, e = hostdata.RestoreAppleDouble(data, hostdata.UnpackOptions{Stat: true}, b)
	if e != nil || r.Code != 0 || len(r.Failures) != 1 || !errors.Is(r.Failures[0].Err, failure) {
		t.Fatal(r, e)
	}
}
func TestUnpackRestoreOwnsSourceAndSlotValues(t *testing.T) {
	f := appledouble.File{FinderInfo: [32]byte{0: 1, 8: 0x40}, Attrs: []appledouble.Attr{{Name: "user.bytes", Value: []byte{1, 2, 3}}}}
	data := unpackData(t, f)
	b := &unpackEdgeBackend{mutate: func(_ string, v []byte) { clear(v) }}
	r, e := hostdata.RestoreAppleDouble(data, hostdata.UnpackOptions{Callback: func(hostdata.UnpackNotice) hostdata.CopyPipelineAction {
		clear(data)
		return hostdata.CopyPipelineContinue
	}}, b)
	if e != nil || !r.ReachedEnd || !r.MakeInvisible || r.Copied != 3 || !bytes.Equal(b.writes["user.bytes"], []byte{1, 2, 3}) || b.writes[appledouble.FinderInfoName][8] != 0x40 {
		t.Fatal(r, e, b.writes)
	}
}
func TestUnpackRestoreStopsBeforeDeferredACL(t *testing.T) {
	data, e := hex.DecodeString(unpackrestore.Images()[1])
	if e != nil {
		t.Fatal(e)
	}
	b := &unpackEdgeBackend{}
	r, e := hostdata.RestoreAppleDouble(data, hostdata.UnpackOptions{Callback: func(hostdata.UnpackNotice) hostdata.CopyPipelineAction { return hostdata.CopyPipelineQuit }}, b)
	if !errors.Is(e, hostdata.ErrXattrRestoreCanceled) || r.ReachedEnd || len(b.writes) != 0 {
		t.Fatal(r, e, b.writes)
	}
}

func TestUnpackRestoreCapturedSandboxPolicy(t *testing.T) {
	data := unpackData(t, appledouble.File{Attrs: []appledouble.Attr{{Name: "com.apple.security.custom", Value: []byte{1}}}})
	for _, sandboxed := range []bool{false, true} {
		for _, intent := range []uint32{0, 1} {
			b := &unpackEdgeBackend{}
			r, e := hostdata.RestoreAppleDouble(data, hostdata.UnpackOptions{Sandboxed: sandboxed, CopyIntent: intent, InitialCopied: 77}, b)
			_, written := b.writes["com.apple.security.custom"]
			if e != nil || !r.ReachedEnd || r.Copied != 77 || written == (sandboxed && intent == 0) {
				t.Fatal(r, e, written)
			}
		}
	}
}
