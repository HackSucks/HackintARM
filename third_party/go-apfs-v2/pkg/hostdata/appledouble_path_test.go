package hostdata

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func pathCapturedFixture(t *testing.T, source, destination *AppleDoubleObject) *CapturedPathContext {
	t.Helper()
	noSetID := false
	return &CapturedPathContext{Source: source, Destination: destination, RealUserUUID: &[16]byte{}, EffectiveUserUUID: &[16]byte{}, SourceProtection: &CapturedPathProtection{}, DestinationProtection: &CapturedPathProtection{}, Creation: &CapturedPathCreation{Umask: 0022, Template: CapturedAppleDoubleObject{State: logicalMetadataFixture(t).Snapshot(), Identities: appledouble.ACLIdentitySnapshot{Version: 1}, Process: QuarantineProcessCapture{Profile: appledouble.QuarantineMacOS26, Absent: true}, NoSetID: &noSetID}}}
}
func TestAppleDoublePathCapturedRoundTrip(t *testing.T) {
	root := t.TempDir()
	source, packed, target := filepath.Join(root, "source"), filepath.Join(root, "packed"), filepath.Join(root, "target")
	if e := os.WriteFile(source, []byte("data"), 0600); e != nil {
		t.Fatal(e)
	}
	objects := pathCapturedFixture(t, objectFixture(t, objectAttr("user.example", "metadata"), objectAttr(ResourceForkName, "fork")), nil)
	options := AppleDoublePathOptions{Operation: PathPackAppleDouble, Pack: DefaultObjectPackOptions(), MaxOpenAttempts: 4, Captured: objects}
	r, e := CopyAppleDoublePath(context.Background(), source, packed, options)
	if e != nil || !r.Lifecycle.Completed || !r.Lifecycle.DestinationCreated || !r.Pack.HeaderWritten || objects.Destination == nil {
		t.Fatalf("%+v %v", r, e)
	}
	encoded, e := os.ReadFile(packed)
	if e != nil {
		t.Fatal(e)
	}
	wire, e := appledouble.DecodeStream(context.Background(), bytes.NewReader(encoded), appledouble.DefaultStreamLimits())
	if e != nil || wire.ResourceFork.Size() != 4 {
		t.Fatal(wire, e)
	}
	if e = os.WriteFile(target, []byte("target data"), 0600); e != nil {
		t.Fatal(e)
	}
	unpackObjects := pathCapturedFixture(t, objects.Destination, objectFixture(t, objectAttr("user.stale", "remove")))
	options = AppleDoublePathOptions{Operation: PathUnpackAppleDouble, Unpack: DefaultObjectUnpackOptions(), MaxOpenAttempts: 4, Captured: unpackObjects}
	u, e := CopyAppleDoublePath(context.Background(), packed, target, options)
	if e != nil || !u.Lifecycle.Completed || !u.Unpack.ReachedEnd {
		t.Fatalf("%+v %v", u, e)
	}
	state, attrs, e := unpackObjects.Destination.LogicalSnapshot()
	if e != nil || state.Stat.Mode != 0100644 {
		t.Fatal(state, e)
	}
	got := map[string]string{}
	for _, a := range attrs {
		b := make([]byte, a.Value.Size())
		if _, e = a.Value.ReadAt(b, 0); e != nil {
			t.Fatal(e)
		}
		got[a.Name] = string(b)
	}
	if got["user.example"] != "metadata" || got[ResourceForkName] != "fork" || got["user.stale"] != "" {
		t.Fatal(got)
	}
	data, e := os.ReadFile(target)
	if e != nil || string(data) != "target data" {
		t.Fatal(string(data), e)
	}
	if e = os.Remove(packed); e != nil {
		t.Fatal("source descriptor retained", e)
	}
	if e = os.Remove(target); e != nil {
		t.Fatal("destination descriptor retained", e)
	}
}
func TestAppleDoublePathFailedPackRemovesDestination(t *testing.T) {
	root := t.TempDir()
	source, destination := filepath.Join(root, "source"), filepath.Join(root, "destination")
	for _, name := range []string{source, destination} {
		if e := os.WriteFile(name, []byte("original"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	objects := pathCapturedFixture(t, objectFixture(t, appledouble.StreamAttr{Name: "broken", Value: objectBrokenValue{size: 8, n: 0, err: errors.New("read failed")}}), objectFixture(t))
	opts := AppleDoublePathOptions{Operation: PathPackAppleDouble, Pack: DefaultObjectPackOptions(), MaxOpenAttempts: 4, Captured: objects}
	r, e := CopyAppleDoublePath(context.Background(), source, destination, opts)
	if e == nil || r.Lifecycle.Code != -1 {
		t.Fatal(r, e)
	}
	if _, e = os.Stat(destination); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("failed pack destination retained", e)
	}
}
func TestAppleDoublePathUnpackFailureRetainsACL(t *testing.T) {
	root := t.TempDir()
	source, target := filepath.Join(root, "bad"), filepath.Join(root, "target")
	if e := os.WriteFile(source, []byte("not AppleDouble"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(target, []byte("keep"), 0600); e != nil {
		t.Fatal(e)
	}
	destination := objectFixture(t)
	logical := destination.meta.(*LogicalMetadata)
	logical.state.Security.Properties.RawSecurity = &appledouble.FileSecurity{ACL: &appledouble.ACL{Entries: []appledouble.ACLEntry{{Principal: [16]byte{2}, Flags: 1, Rights: 2}}}}
	objects := pathCapturedFixture(t, objectFixture(t), destination)
	objects.RealUserUUID = &[16]byte{3}
	objects.EffectiveUserUUID = &[16]byte{3}
	opts := AppleDoublePathOptions{Operation: PathUnpackAppleDouble, Unpack: DefaultObjectUnpackOptions(), MaxOpenAttempts: 4, Captured: objects}
	r, e := CopyAppleDoublePath(context.Background(), source, target, opts)
	if e == nil || r.Lifecycle.Code != -1 {
		t.Fatal(r, e)
	}
	state, _, e := destination.LogicalSnapshot()
	if e != nil || state.Stat.Mode != 0100644 || len(state.Security.Properties.RawSecurity.ACL.Entries) != 2 {
		t.Fatal(state, e)
	}
	data, e := os.ReadFile(target)
	if e != nil || string(data) != "keep" {
		t.Fatal(string(data), e)
	}
}
