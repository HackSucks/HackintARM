package hostdata

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func objectFixture(t *testing.T, attrs ...appledouble.StreamAttr) *AppleDoubleObject {
	t.Helper()
	noSetID := false
	o, err := NewCapturedAppleDoubleObject(CapturedAppleDoubleObject{State: logicalMetadataFixture(t).Snapshot(), Attributes: attrs, Identities: appledouble.ACLIdentitySnapshot{Version: 1}, Process: QuarantineProcessCapture{Profile: appledouble.QuarantineMacOS26, Absent: true}, NoSetID: &noSetID})
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func objectAttr(name, value string) appledouble.StreamAttr {
	return appledouble.StreamAttr{Name: name, Value: bytes.NewReader([]byte(value))}
}

type objectOutput []byte

func (o *objectOutput) WriteAt(p []byte, off int64) (int, error) {
	end := int(off) + len(p)
	if end > len(*o) {
		*o = append(*o, make([]byte, end-len(*o))...)
	}
	return copy((*o)[int(off):], p), nil
}

func TestAppleDoubleObjectRoundTrip(t *testing.T) {
	ctx := context.Background()
	source := objectFixture(t, objectAttr("user.example", "metadata"), objectAttr(appledouble.ResourceForkName, "fork"))
	packed := objectFixture(t)
	var output objectOutput
	options := DefaultObjectPackOptions()
	options.Stat, options.NoCache = true, true
	p, err := PackAppleDoubleObject(ctx, source, packed, &output, options)
	if err != nil || !p.Lifecycle.Completed || !p.Pack.HeaderWritten {
		t.Fatalf("%+v %v", p, err)
	}
	decoded, err := appledouble.DecodeStream(ctx, bytes.NewReader(output), appledouble.DefaultStreamLimits())
	if err != nil || decoded.ResourceFork.Size() != 4 {
		t.Fatalf("%+v %v", decoded, err)
	}
	target := objectFixture(t, objectAttr("user.stale", "remove"))
	unpack := DefaultObjectUnpackOptions()
	unpack.NoCache = true
	notices := 0
	unpack.Callback = func(UnpackNotice) CopyPipelineAction { notices++; return CopyPipelineContinue }
	u, err := UnpackAppleDoubleObject(ctx, bytes.NewReader(output), packed, target, unpack)
	if err != nil || !u.Lifecycle.Completed || !u.Unpack.ReachedEnd || notices == 0 {
		t.Fatalf("%+v %v notices=%d", u, err, notices)
	}
	state, attrs, err := target.LogicalSnapshot()
	if err != nil || state.Stat.Mode != 0100644 {
		t.Fatal(state, err)
	}
	got := map[string]string{}
	for _, a := range attrs {
		b := make([]byte, a.Value.Size())
		if _, err := a.Value.ReadAt(b, 0); err != nil {
			t.Fatal(err)
		}
		got[a.Name] = string(b)
	}
	if got["user.example"] != "metadata" || got[appledouble.ResourceForkName] != "fork" || got["user.stale"] != "" {
		t.Fatal(got)
	}
	if len(source.IdentitySnapshot().Principals) != 0 {
		t.Fatal("unexpected identity lookup")
	}
}

func TestAppleDoubleObjectValidation(t *testing.T) {
	o := objectFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output objectOutput
	for _, c := range []context.Context{nil, ctx} {
		if _, err := PackAppleDoubleObject(c, o, o, &output, DefaultObjectPackOptions()); err == nil {
			t.Fatal("pack context")
		}
		if _, err := UnpackAppleDoubleObject(c, bytes.NewReader(nil), o, o, DefaultObjectUnpackOptions()); err == nil {
			t.Fatal("unpack context")
		}
		if _, err := NewHostAppleDoubleObject(c, nil); err == nil {
			t.Fatal("host context")
		}
	}
	if _, err := NewHostAppleDoubleObject(context.Background(), nil); err == nil {
		t.Fatal("nil held file")
	}
	p := DefaultObjectPackOptions()
	p.HasQuarantine = true
	if _, err := PackAppleDoubleObject(context.Background(), o, o, &output, p); err == nil {
		t.Fatal("injected quarantine")
	}
	u := DefaultObjectUnpackOptions()
	u.Sandboxed = true
	if _, err := UnpackAppleDoubleObject(context.Background(), bytes.NewReader(nil), o, o, u); err == nil {
		t.Fatal("injected sandbox")
	}
	c := CapturedAppleDoubleObject{State: logicalMetadataFixture(t).Snapshot(), Identities: appledouble.ACLIdentitySnapshot{Version: 1}, Process: QuarantineProcessCapture{Profile: appledouble.QuarantineMacOS26, Agent: []byte("agent"), Metadata: []byte("meta"), Tracking: []byte("track")}}
	x, err := NewCapturedAppleDoubleObject(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Process.Agent[0] = 'X'
	c.Process.Metadata[0] = 'X'
	c.Process.Tracking[0] = 'X'
	if string(x.process.Agent) != "agent" || string(x.process.Metadata) != "meta" || string(x.process.Tracking) != "track" {
		t.Fatal("borrowed process bytes")
	}
	c.Process.Profile = 255
	if _, err := NewCapturedAppleDoubleObject(c); err == nil {
		t.Fatal("invalid process")
	}
	c.State.Stat.Mode++
	if _, err := NewCapturedAppleDoubleObject(c); err == nil {
		t.Fatal("invalid state")
	}
}

type objectBrokenValue struct {
	size int64
	n    int
	err  error
}

func (v objectBrokenValue) Size() int64                           { return v.size }
func (v objectBrokenValue) ReadAt(p []byte, _ int64) (int, error) { return min(v.n, len(p)), v.err }

func TestAppleDoubleObjectAttributeStorage(t *testing.T) {
	meta := logicalMetadataFixture(t)
	for _, attrs := range [][]appledouble.StreamAttr{
		{objectAttr("", "")}, {objectAttr("a\x00b", "")}, {objectAttr(strings.Repeat("a", 128), "")},
		{objectAttr("a", ""), objectAttr("a", "")}, {{Name: "a", Value: objectBrokenValue{size: -1}}},
	} {
		if _, err := newLogicalObjectAttributes(meta, attrs, nil); err == nil {
			t.Fatal("invalid attributes", attrs)
		}
	}
	a, err := newLogicalObjectAttributes(meta, []appledouble.StreamAttr{{Name: "empty"}, objectAttr(appledouble.ResourceForkName, "original")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.noSetID(); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := a.names(0); !errors.Is(err, ErrXattrTooLarge) {
		t.Fatal(err)
	}
	if _, err := a.size("missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if _, err := a.read("missing", nil); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if _, err := a.read(appledouble.ResourceForkName, nil); !errors.Is(err, ErrXattrTooLarge) {
		t.Fatal(err)
	}
	if _, err := a.read("empty", nil); err != nil {
		t.Fatal(err)
	}
	if err := a.remove("missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	for _, name := range []string{"", "a\x00b", strings.Repeat("a", 128)} {
		if err := a.write(name, nil); err == nil {
			t.Fatal(name)
		}
	}
	if err := a.write(appledouble.FinderInfoName, nil); err == nil {
		t.Fatal("short finder")
	}
	for _, b := range [][]byte{make([]byte, 32), append([]byte{1}, make([]byte, 31)...), make([]byte, 32)} {
		if err := a.write(appledouble.FinderInfoName, b); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.write(appledouble.ResourceForkName, nil); err != nil {
		t.Fatal(err)
	}
	if err := a.write(appledouble.ResourceForkName, []byte("new")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	if n, err := a.read(appledouble.ResourceForkName, buf); n != 8 || err != nil || string(buf) != "newginal" {
		t.Fatal(n, err, string(buf))
	}
	a.values["broken"] = objectBrokenValue{size: 2}
	if _, err := a.read("broken", make([]byte, 2)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	a.values["broken"] = objectBrokenValue{size: 2, n: 2, err: io.EOF}
	if _, err := a.read("broken", make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
}

func TestAppleDoubleObjectForkPrefix(t *testing.T) {
	v := &prefixObjectValue{head: []byte("new"), tail: bytes.NewReader([]byte("original"))}
	for _, tt := range []struct {
		off     int64
		size, n int
		want    string
		err     error
	}{
		{-1, 1, 0, "", os.ErrInvalid}, {0, 0, 0, "", nil}, {8, 1, 0, "", io.EOF}, {0, 2, 2, "ne", nil}, {2, 4, 4, "wgin", nil}, {3, 7, 5, "ginal", io.EOF},
	} {
		p := make([]byte, tt.size)
		n, err := v.ReadAt(p, tt.off)
		if n != tt.n || !errors.Is(err, tt.err) || string(p[:n]) != tt.want {
			t.Fatal(tt, n, err, string(p[:n]))
		}
	}
	v.tail = objectBrokenValue{size: 8, err: os.ErrPermission}
	if _, err := v.ReadAt(make([]byte, 4), 3); !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	v.tail = objectBrokenValue{size: 8}
	if _, err := v.ReadAt(make([]byte, 4), 3); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
}
