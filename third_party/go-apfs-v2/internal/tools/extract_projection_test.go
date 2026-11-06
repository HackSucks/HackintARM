package tools

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"testing/fstest"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

type projectionRecorder struct {
	events   []string
	failures map[string]error
}

func (p *projectionRecorder) call(s string) error {
	p.events = append(p.events, s)
	return p.failures[s]
}
func (p *projectionRecorder) SetXattr(n string, _ []byte) error        { return p.call("xattr:" + n) }
func (p *projectionRecorder) Security(*appledouble.FileSecurity) error { return p.call("security") }
func (p *projectionRecorder) Chown(uint32, uint32) error               { return p.call("ownership") }
func (p *projectionRecorder) Chmod(uint16) error                       { return p.call("mode") }
func (p *projectionRecorder) SetTimes(time.Time, time.Time) error      { return p.call("times") }
func (p *projectionRecorder) SetBirth(time.Time) error                 { return p.call("birth") }
func (p *projectionRecorder) Chflags(uint32) error                     { return p.call("flags") }
func projectionRecord() metatransport.Record {
	u, g, m, f := uint32(1), uint32(2), uint32(06754), uint32(hostdata.UFCompressed)
	tm := time.Unix(100, 0)
	return metatransport.Record{Original: "file", Materialized: "file", Kind: "file", MaterializedKind: "file", Darwin: metatransport.DarwinState{UID: &u, GID: &g, Mode: &m, Flags: &f, Birth: &tm, Modify: &tm, Access: &tm, Change: &tm}}
}
func TestProjectionExecutionAndOutcomes(t *testing.T) {
	ctx := context.Background()
	e := &Extractor{}
	b := &projectionRecorder{failures: map[string]error{"ownership": fs.ErrPermission, "mode": io.ErrClosedPipe}}
	security, err := (&appledouble.FileSecurity{}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	attrs := map[string]appledouble.Value{"z": bytes.NewReader([]byte{1}), hostdata.SecurityName: bytes.NewReader(security), hostdata.DecmpfsName: bytes.NewReader(projectionCompression(4)), hostdata.ResourceForkName: bytes.NewReader([]byte{4})}
	r := projectionRecord()
	if err = e.applyProjection(ctx, r, attrs, 1024, b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(b.events, []string{"security", "xattr:z", "ownership", "mode", "times", "birth", "flags"}) {
		t.Fatal(b.events)
	}
	if !errors.Is(e.projectionError(), io.ErrClosedPipe) {
		t.Fatal(e.projectionError())
	}
	result := e.NativeProjectionResults()
	if len(result) != 12 {
		t.Fatal(result)
	}
	result[0].Field = "changed"
	if e.NativeProjectionResults()[0].Field == "changed" {
		t.Fatal("report aliases")
	}
	for _, r := range result {
		if r.Field == "ownership" && r.Status != ProjectionRetained {
			t.Fatal(r)
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if err = e.applyProjection(ctx, r, attrs, 1024, b); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	e = &Extractor{}
	if err = e.applyProjection(context.Background(), metatransport.Record{}, map[string]appledouble.Value{hostdata.SecurityName: bytes.NewReader([]byte{1}), "large": bytes.NewReader([]byte{1, 2})}, 1, &projectionRecorder{}); err != nil {
		t.Fatal(err)
	}
	for _, r := range e.NativeProjectionResults() {
		if r.Status != ProjectionRetained {
			t.Fatal(r)
		}
	}
}

type projectionFaultValue struct {
	size int64
	n    int
	err  error
}

func (v projectionFaultValue) Size() int64                           { return v.size }
func (v projectionFaultValue) ReadAt(p []byte, _ int64) (int, error) { return min(v.n, len(p)), v.err }
func TestProjectionValueReads(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := projectionBytes(ctx, bytes.NewReader(nil), 1); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, v := range []appledouble.Value{nil, projectionFaultValue{size: -1}, projectionFaultValue{size: 2}, projectionFaultValue{size: 1, err: io.EOF}, projectionFaultValue{size: 1, n: 1, err: io.ErrClosedPipe}} {
		if _, err := projectionBytes(context.Background(), v, 1); err == nil {
			t.Fatal("accepted bad value")
		}
	}
	if _, err := projectionBytes(context.Background(), projectionFaultValue{size: 1, n: 1, err: io.EOF}, 1); err != nil {
		t.Fatal(err)
	}
}
func TestProjectionReadback(t *testing.T) {
	e := &Extractor{}
	p, m, s := projectionFixture(t)
	_ = p
	_ = m
	attrs, err := s.StoreAttributes(context.Background(), map[string][]byte{"exact": {1}, "different": {1}, "missing": {1}})
	if err != nil {
		t.Fatal(err)
	}
	r := metatransport.Record{Original: "file", Attributes: attrs}
	for _, name := range []string{"exact", "different", "missing"} {
		e.projection("file", "xattr:"+name, nil)
	}
	e.projection("other", "xattr:exact", nil)
	e.projection("file", "mode", nil)
	e.projection("file", "xattr:failed", fs.ErrPermission)
	e.verifyProjection(r, map[string][]byte{"exact": {1}, "different": {2}})
	results := e.NativeProjectionResults()
	if !results[0].Verified || results[1].Status != ProjectionNormalized || results[2].Status != ProjectionNormalized || results[3].Verified {
		t.Fatal(results)
	}
}
func projectionFixture(t *testing.T) (string, string, *metatransport.Store) {
	t.Helper()
	base := t.TempDir()
	p, m := filepath.Join(base, "p"), filepath.Join(base, "m")
	os.Mkdir(p, 0700)
	os.Mkdir(m, 0700)
	s, e := metatransport.Open(p, m, metatransport.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return p, m, s
}
func TestProjectionCarrierIntegration(t *testing.T) {
	v := carrierVolume{MapFS: fstest.MapFS{"file": {Data: []byte("body")}}, attrs: map[string][]byte{"user.project": []byte("value")}}
	e := newCarrierExtractor(t, v)
	e.ProjectNative = true
	e.Xattrs = true
	if err := e.ExtractAll(); err != nil {
		t.Fatal(err)
	}
	if len(e.NativeProjectionResults()) != 2 {
		t.Fatal(e.NativeProjectionResults())
	}
	for _, r := range e.NativeProjectionResults() {
		if r.Status == ProjectionFailed {
			t.Fatal(r)
		}
	}
	store, err := metatransport.Open(e.Destination, e.MetadataRoot, metatransport.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	m, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range m.Records {
		if !r.NativeCaptured && !r.NativeUnsupported {
			t.Fatal("baseline missing")
		}
	}
	noCarrier := NewExtractor(v, t.TempDir())
	noCarrier.ProjectNative = true
	if err = noCarrier.ExtractAll(); err == nil {
		t.Fatal("no carrier accepted")
	}
	if err = noCarrier.ExtractByPath("/file", false); err == nil {
		t.Fatal("no carrier accepted")
	}
}
func TestProjectionCarrierFailures(t *testing.T) {
	for _, test := range []string{"cancel", "symlink", "open", "attrs", "apply", "unsupported", "capture", "store", "success"} {
		t.Run(test, func(t *testing.T) {
			p, _, s := projectionFixture(t)
			os.WriteFile(filepath.Join(p, "file"), []byte("body"), 0600)
			root, err := os.OpenRoot(p)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			e := &Extractor{}
			r := metatransport.Record{Original: "file", Materialized: "file", Kind: "file", MaterializedKind: "file"}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			capture := func(context.Context, *os.File, hostdata.XattrCaptureLimits) (map[string][]byte, error) {
				return map[string][]byte{}, nil
			}
			maker := func(*os.File) projectionBackend { return &projectionRecorder{} }
			switch test {
			case "cancel":
				cancel()
			case "symlink":
				r.Kind = "symlink"
			case "open":
				r.Materialized = "missing"
			case "attrs":
				r.Attributes = []metatransport.Attribute{{Name: "bad", Value: metatransport.BlobRef{SHA256: "invalid"}}}
			case "apply":
				r.Attributes, _ = s.StoreAttributes(ctx, map[string][]byte{"a": {1}})
				maker = func(*os.File) projectionBackend { cancel(); return &projectionRecorder{} }
			case "unsupported":
				capture = func(context.Context, *os.File, hostdata.XattrCaptureLimits) (map[string][]byte, error) {
					return nil, hostdata.ErrXattrUnsupported
				}
			case "capture":
				capture = func(context.Context, *os.File, hostdata.XattrCaptureLimits) (map[string][]byte, error) {
					return nil, io.ErrClosedPipe
				}
			case "store":
				capture = func(context.Context, *os.File, hostdata.XattrCaptureLimits) (map[string][]byte, error) {
					s.Close()
					return map[string][]byte{"a": {1}}, nil
				}
			}
			records := []metatransport.Record{r}
			err = e.projectCarrier(ctx, root, s, records, hostdata.XattrCaptureLimits{ValueBytes: 100}, maker, capture)
			wantError := test == "cancel" || test == "attrs" || test == "apply" || test == "store"
			if (err != nil) != wantError {
				t.Fatal(test, err)
			}
			if test == "capture" && !errors.Is(e.projectionError(), io.ErrClosedPipe) {
				t.Fatal(e.projectionError())
			}
			if test == "unsupported" && !records[0].NativeUnsupported {
				t.Fatal(records)
			}
		})
	}
}
func TestProjectionNativeBindings(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "file"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b := newNativeProjection(f)
	// These calls test the held binding on every host; native constraints remain
	// explicit results, while the logical operation tests above are identical.
	for name, call := range map[string]func() error{
		"attr":     func() error { return b.SetXattr("user.project", []byte{1}) },
		"mode":     func() error { return b.Chmod(0600) },
		"owner":    func() error { return b.Chown(uint32(os.Getuid()), uint32(os.Getgid())) },
		"times":    func() error { return b.SetTimes(time.Unix(100, 0), time.Unix(100, 0)) },
		"birth":    func() error { return b.SetBirth(time.Unix(100, 0)) },
		"flags":    func() error { return b.Chflags(0) },
		"security": func() error { return b.Security(&appledouble.FileSecurity{}) },
	} {
		e := &Extractor{}
		e.projection("file", name, call())
		if e.projectionResults[0].Status == ProjectionFailed {
			t.Fatal(name, e.projectionResults)
		}
	}
	invalid := nativeProjection{}
	if err := invalid.Security(&appledouble.FileSecurity{Trailing: []byte{1}}); !errors.Is(err, appledouble.ErrFileSecurity) {
		t.Fatal(err)
	}
	p := nativeProjection{file: f, heldErr: errors.ErrUnsupported}
	if !errors.Is(p.Security(&appledouble.FileSecurity{}), errors.ErrUnsupported) || !errors.Is(p.Chflags(0), errors.ErrUnsupported) {
		t.Fatal("unsupported discarded")
	}
}

func projectionCompression(method uint32) []byte {
	p := make([]byte, 16)
	copy(p, "fpmc")
	binary.LittleEndian.PutUint32(p[4:], method)
	return p
}

func TestProjectionIndependentResourceFork(t *testing.T) {
	for _, method := range []uint32{3, 4, 5} {
		e := &Extractor{}
		b := &projectionRecorder{}
		attrs := map[string]appledouble.Value{hostdata.DecmpfsName: bytes.NewReader(projectionCompression(method)), hostdata.ResourceForkName: bytes.NewReader([]byte("fork"))}
		if err := e.applyProjection(context.Background(), metatransport.Record{}, attrs, 1024, b); err != nil {
			t.Fatal(err)
		}
		if (len(b.events) == 1) != (method == 3) {
			t.Fatal(method, b.events)
		}
		if method == 5 && e.projectionResults[0].Field != "compression-shape" {
			t.Fatal(e.projectionResults)
		}
	}
}

func TestProjectionStreamFallbackAndReadback(t *testing.T) {
	ctx := context.Background()
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	p := nativeProjection{file: dir, heldErr: errors.ErrUnsupported}
	if err := p.ResourceFork(ctx, bytes.NewReader([]byte{1}), 0); !errors.Is(err, hostdata.ErrXattrTooLarge) {
		t.Fatal(err)
	}
	// A directory has no native fork descriptor. The bounded xattr fallback must
	// report the host's real result instead of pretending the fork was applied.
	got := p.ResourceFork(ctx, bytes.NewReader([]byte{1}), 1)
	want := p.SetXattr(hostdata.ResourceForkName, []byte{1})
	if (got == nil) != (want == nil) {
		t.Fatal(got, want)
	}
	tm := time.Now().Add(-time.Hour)
	if err := p.SetTimes(tm, tm); err != nil && !projectionConstraint(err) {
		t.Fatal(err)
	}
	e := &Extractor{}
	ref := metatransport.BlobRef{Size: 1, SHA256: "original"}
	r := metatransport.Record{Original: "file", Attributes: []metatransport.Attribute{{Name: "exact", Value: ref}, {Name: "changed", Value: ref}, {Name: "missing", Value: ref}}}
	for _, name := range []string{"exact", "changed", "missing"} {
		e.projection("file", "xattr:"+name, nil)
	}
	e.verifyProjectionRefs(r, []metatransport.Attribute{{Name: "exact", Value: ref}, {Name: "changed", Value: metatransport.BlobRef{Size: 2, SHA256: "changed"}}})
	results := e.NativeProjectionResults()
	if !results[0].Verified || results[1].Status != ProjectionNormalized || results[2].Status != ProjectionNormalized {
		t.Fatal(results)
	}
}

func TestProjectionXattrStats(t *testing.T) {
	ctx := context.Background()
	_, _, store := projectionFixture(t)
	attrs := map[string][]byte{"applied": {1}, "normalized": {2}, "retained": {3}, "failed": {4}}
	r := projectionRecord()
	var err error
	r.Attributes, err = store.StoreAttributes(ctx, attrs)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]appledouble.Value{}
	for name, value := range attrs {
		values[name] = bytes.NewReader(value)
	}
	e := &Extractor{xattrsRestored: 2, xattrsUnwritable: 3}
	backend := &projectionRecorder{failures: map[string]error{"xattr:retained": errors.ErrUnsupported, "xattr:failed": io.ErrClosedPipe, "ownership": os.ErrPermission}}
	if err := e.applyProjection(ctx, r, values, 1024, backend); err != nil {
		t.Fatal(err)
	}
	e.verifyProjection(r, map[string][]byte{"applied": {1}, "normalized": {9}})
	if !errors.Is(e.projectionError(), io.ErrClosedPipe) {
		t.Fatal("statistics masked the failed native write")
	}
	for range 2 {
		if written, unwritable := e.XattrStats(); written != 4 || unwritable != 5 {
			t.Fatalf("native outcomes or legacy writes miscounted: %d, %d", written, unwritable)
		}
	}
}
