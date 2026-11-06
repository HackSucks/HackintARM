package tools

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

type projectionMetadataFixture struct {
	stat            hostdata.StatCopySource
	security        *appledouble.FileSecurity
	statErr, aclErr error
}

func (p projectionMetadataFixture) WriteSecurity(aclmeta.DarwinChmodArguments) error { return nil }
func (p projectionMetadataFixture) Chflags(uint32) error                             { return nil }
func (p projectionMetadataFixture) CaptureStat() (hostdata.StatCopySource, error) {
	return p.stat, p.statErr
}
func (p projectionMetadataFixture) CaptureACL() (aclmeta.ACLMetadata, error) {
	return aclmeta.ACLMetadata{Security: p.security}, p.aclErr
}
func TestProjectionNativeReadback(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "file"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := projectionRecord()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	tm := info.ModTime()
	r.Darwin.Modify = &tm
	security := &appledouble.FileSecurity{}
	raw, err := security.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	_, _, s := projectionFixture(t)
	r.Attributes, err = s.StoreAttributes(context.Background(), map[string][]byte{hostdata.SecurityName: raw})
	if err != nil {
		t.Fatal(err)
	}
	captured := hostdata.StatCopySource{UID: *r.Darwin.UID, GID: *r.Darwin.GID, Flags: 0, Times: hostdata.FileTimes{Access: *r.Darwin.Access, Birth: *r.Darwin.Birth}}
	fixture := projectionMetadataFixture{stat: captured, security: security}
	p := nativeProjection{file: f, held: fixture}
	checks, err := p.Readback(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"modify", "ownership", "access", "birth", "flags", "xattr:" + hostdata.SecurityName} {
		if !checks[field] {
			t.Fatal(field, checks)
		}
	}
	p.heldErr = errors.ErrUnsupported
	checks, err = p.Readback(r)
	if err != nil || !checks["modify"] || len(checks) != 2 {
		t.Fatal(checks, err)
	}
	p.heldErr = io.ErrClosedPipe
	if _, err = p.Readback(r); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	p.heldErr = nil
	fixture.statErr = io.ErrClosedPipe
	p.held = fixture
	if _, err = p.Readback(r); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	fixture.statErr = nil
	fixture.aclErr = io.ErrClosedPipe
	p.held = fixture
	if _, err = p.Readback(r); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	bad := &appledouble.FileSecurity{ACL: &appledouble.ACL{}, NoACLFlags: [4]byte{1}}
	if _, err = projectionChecks(r, info, &captured, bad); !errors.Is(err, appledouble.ErrFileSecurity) {
		t.Fatal(err)
	}
	f.Close()
	// Preserve the host's actual Stat failure, including Windows' invalid
	// handle error, rather than requiring Unix's closed-file classification.
	_, statErr := f.Stat()
	var statPathError *os.PathError
	if !errors.As(statErr, &statPathError) {
		t.Fatal("expected closed-file stat failure", statErr)
	}
	if _, err = p.Readback(r); !errors.Is(err, statPathError.Err) {
		t.Fatal(err)
	}
}
func TestProjectionReadbackDisposition(t *testing.T) {
	e := &Extractor{}
	e.projection("file", "mode", nil)
	e.projection("file", "modify", nil)
	e.projection("file", "flags", io.ErrClosedPipe)
	e.projection("other", "mode", nil)
	e.projection("file", "unknown", nil)
	e.projectionResults[0].Status = ProjectionNormalized
	e.verifyProjectionChecks(metatransport.Record{Original: "file"}, map[string]bool{"mode": true, "modify": false, "flags": true})
	got := e.NativeProjectionResults()
	if !got[0].Verified || got[0].Status != ProjectionApplied || got[1].Status != ProjectionNormalized || got[2].Status != ProjectionFailed || got[3].Verified || got[4].Verified {
		t.Fatal(got)
	}
}

type projectionReadbackFailure struct{ projectionRecorder }

func (*projectionReadbackFailure) Readback(metatransport.Record) (map[string]bool, error) {
	return nil, io.ErrClosedPipe
}
func TestProjectionReadbackFailureRetainsCarrier(t *testing.T) {
	p, _, s := projectionFixture(t)
	os.WriteFile(filepath.Join(p, "file"), nil, 0600)
	root, err := os.OpenRoot(p)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	e := &Extractor{}
	records := []metatransport.Record{{Original: "file", Materialized: "file", Kind: "file"}}
	err = e.projectCarrier(context.Background(), root, s, records, hostdata.XattrCaptureLimits{}, func(*os.File) projectionBackend { return &projectionReadbackFailure{} }, func(context.Context, *os.File, hostdata.XattrCaptureLimits) (map[string][]byte, error) {
		return nil, nil
	})
	if err != nil || !errors.Is(e.projectionError(), io.ErrClosedPipe) {
		t.Fatal(err, e.projectionError())
	}
}

func TestProjectionAllStatMismatches(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "file"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	r := projectionRecord()
	checks, err := projectionChecks(r, info, &hostdata.StatCopySource{Flags: 8, Times: hostdata.FileTimes{Birth: time.Time{}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"mode", "modify", "ownership", "access", "birth", "flags"} {
		if checks[field] {
			t.Fatal(field)
		}
	}
}

func (projectionMetadataFixture) SetTimes(time.Time, time.Time) error { return nil }

// Exercise the held-provider protocol independently of the host's ability to
// enforce Darwin permissions. Real Darwin binding tests qualify that provider.
func TestProjectionHeldProviderDispatch(t *testing.T) {
	p := nativeProjection{held: projectionMetadataFixture{}}
	if err := p.Security(&appledouble.FileSecurity{}); err != nil {
		t.Fatal(err)
	}
	if err := p.Chflags(0); err != nil {
		t.Fatal(err)
	}
	if err := p.SetTimes(time.Unix(1, 0), time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
}

type projectionStreamFailure struct{ projectionRecorder }

func (*projectionStreamFailure) ResourceFork(context.Context, appledouble.Value, int) error {
	return io.ErrClosedPipe
}
func TestProjectionStreamingForkFailure(t *testing.T) {
	e := &Extractor{}
	backend := &projectionStreamFailure{}
	attrs := map[string]appledouble.Value{hostdata.ResourceForkName: projectionFaultValue{size: 1}}
	if err := e.applyProjection(context.Background(), metatransport.Record{Original: "file"}, attrs, 0, backend); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(e.projectionError(), io.ErrClosedPipe) || len(backend.events) != 0 {
		t.Fatal(e.NativeProjectionResults(), backend.events)
	}
	// A failure before opening the native fork must also remain an explicit error.
	p := nativeProjection{}
	if err := p.ResourceFork(context.Background(), attrs[hostdata.ResourceForkName], 1); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
}
