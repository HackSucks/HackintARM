package hostdata

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

type pathLifecycleModel struct {
	original        PathDestinationState
	mode            uint32
	steps           []string
	failures        map[string]error
	cancelAt        string
	cancel          context.CancelFunc
	same, retryMode bool
	opened          bool
	route           CopyStageResult
	prepared        aclmeta.DarwinChmodProperties
	routeSteps      []HeldLifecycleStep
	temporaryClose  []HeldLifecycleStep
}

func newPathLifecycleModel() *pathLifecycleModel {
	mode := uint32(0400)
	return &pathLifecycleModel{original: PathDestinationState{Stat: StatCopySource{Mode: 0100400, UID: 51, GID: 20}, Properties: aclmeta.DarwinChmodProperties{Mode: &mode}}, mode: mode, failures: map[string]error{}}
}
func (m *pathLifecycleModel) call(name string) error {
	m.steps = append(m.steps, name)
	if m.cancel != nil && name == m.cancelAt {
		m.cancel()
	}
	return m.failures[name]
}
func (m *pathLifecycleModel) SameObject() (bool, error) { return m.same, m.call("same") }
func (m *pathLifecycleModel) CaptureDestination() (PathDestinationState, error) {
	return m.original, m.call("capture")
}
func (m *pathLifecycleModel) RealUserUUID() ([16]byte, error) {
	return [16]byte{7}, m.call("real-user")
}
func (m *pathLifecycleModel) ApplyTemporarySecurity(p aclmeta.DarwinChmodProperties) error {
	m.prepared = p
	if e := m.call("temporary"); e != nil {
		return e
	}
	if p.Mode != nil {
		m.mode = *p.Mode
	}
	return nil
}
func (m *pathLifecycleModel) Open(_ context.Context, attempts uint64) (PathOpenResult, error) {
	if attempts != 4 {
		panic("open budget not passed through")
	}
	m.opened = true
	if m.retryMode {
		m.mode = 0600
	}
	return PathOpenResult{PermissionsChanged: m.retryMode}, m.call("open")
}
func (m *pathLifecycleModel) ValidateDestination() error { return m.call("validate") }
func (m *pathLifecycleModel) CloseTemporarySecurity() []HeldLifecycleStep {
	if len(m.temporaryClose) > 0 {
		_ = m.call("close-temporary")
	}
	return m.temporaryClose
}
func (m *pathLifecycleModel) ConfigureIO() []HeldLifecycleStep {
	return []HeldLifecycleStep{{Operation: "source-no-cache", Err: m.call("source-cache")}, {Operation: "destination-no-cache", Err: m.call("destination-cache")}}
}
func (m *pathLifecycleModel) Run(context.Context) (CopyStageResult, []HeldLifecycleStep) {
	_ = m.call("route")
	return m.route, m.routeSteps
}
func (m *pathLifecycleModel) RestoreBSD(s StatCopySource, path bool) []HeldLifecycleStep {
	prefix := "held-"
	if path {
		prefix = "path-"
	}
	owner := m.call(prefix + "owner")
	mode := m.call(prefix + "mode")
	if mode == nil {
		m.mode = s.Mode & 07777
	}
	return []HeldLifecycleStep{{Operation: prefix + "owner", Err: owner}, {Operation: prefix + "mode", Err: mode}}
}
func (m *pathLifecycleModel) ResetSecurity() []HeldLifecycleStep {
	return []HeldLifecycleStep{{Operation: "reset-security", Err: m.call("reset")}}
}
func (m *pathLifecycleModel) RemoveSource() error { return m.call("remove-source") }
func (m *pathLifecycleModel) Close() []HeldLifecycleStep {
	if !m.opened {
		return nil
	}
	m.opened = false
	return []HeldLifecycleStep{{Operation: "close-source", Err: m.call("close-source")}, {Operation: "close-destination", Err: m.call("close-destination")}}
}
func pathOptions() PathLifecycleOptions { return PathLifecycleOptions{MaxOpenAttempts: 4} }

func TestPathLifecycleExistingDestination(t *testing.T) {
	m := newPathLifecycleModel()
	r, e := CopyPathMetadata(context.Background(), pathOptions(), m)
	want := []string{"same", "capture", "temporary", "open", "validate", "source-cache", "destination-cache", "route", "held-owner", "held-mode", "reset", "close-source", "close-destination"}
	if e != nil || !r.Completed || r.Code != 0 || !r.PermissionsChanged || r.DestinationCreated || m.mode != 0400 || !reflect.DeepEqual(m.steps, want) {
		t.Fatalf("%+v %v mode=%o steps=%v", r, e, m.mode, m.steps)
	}
	if *m.original.Properties.Mode != 0400 || *m.prepared.Mode != 0600 {
		t.Fatal("original permissions mutated or temporary permissions missing")
	}
}

func TestPathLifecycleFailureRestoresAndCloses(t *testing.T) {
	primary, owner, mode, closeSource, closeDestination := errors.New("route"), errors.New("owner"), errors.New("mode"), errors.New("source-close"), errors.New("destination-close")
	m := newPathLifecycleModel()
	m.route = CopyStageResult{Code: -1, Err: primary}
	m.failures["path-owner"], m.failures["path-mode"] = owner, mode
	m.failures["close-source"], m.failures["close-destination"] = closeSource, closeDestination
	r, e := CopyPathMetadata(context.Background(), pathOptions(), m)
	for _, cause := range []error{primary, owner, mode, closeSource, closeDestination} {
		if !errors.Is(e, cause) {
			t.Fatal("lost failure", cause, e)
		}
	}
	if r.Completed || r.Code != -1 || strings.Contains(strings.Join(m.steps, " "), "reset") || m.opened {
		t.Fatal(r, m.steps)
	}
	if got := m.steps[len(m.steps)-4:]; !reflect.DeepEqual(got, []string{"path-owner", "path-mode", "close-source", "close-destination"}) {
		t.Fatal(got)
	}
}

func TestPathLifecycleCancellation(t *testing.T) {
	for _, at := range []string{"capture", "real-user", "temporary", "open", "source-cache", "route"} {
		t.Run(at, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			m := newPathLifecycleModel()
			m.cancel, m.cancelAt = cancel, at
			if at == "real-user" {
				m.original.Properties.RawSecurity = &appledouble.FileSecurity{ACL: &appledouble.ACL{}}
			}
			r, e := CopyPathMetadata(ctx, pathOptions(), m)
			if !errors.Is(e, context.Canceled) || r.Completed || r.Code != -1 || m.mode != 0400 || m.opened {
				t.Fatal(r, e, m.steps, m.mode)
			}
			for _, step := range m.steps {
				if step == "reset" || step == "remove-source" {
					t.Fatal("success cleanup after cancellation", m.steps)
				}
			}
		})
	}
}

func TestPathLifecycleAcquisitionAndIgnoredErrors(t *testing.T) {
	failure := errors.New("injected")
	cases := []struct {
		name      string
		configure func(*pathLifecycleModel, *PathLifecycleOptions)
		code      int
		match     error
		wantReset bool
	}{
		{"missing", func(m *pathLifecycleModel, _ *PathLifecycleOptions) { m.failures["capture"] = os.ErrNotExist }, 0, nil, true},
		{"source-open", func(m *pathLifecycleModel, _ *PathLifecycleOptions) { m.failures["open"] = failure }, -1, failure, false},
		{"temporary-failure", func(m *pathLifecycleModel, _ *PathLifecycleOptions) { m.failures["temporary"] = failure }, -1, failure, false},
		{"unknown-destination", func(m *pathLifecycleModel, _ *PathLifecycleOptions) { m.failures["capture"] = failure }, -1, ErrPathLifecycleUndefined, false},
		{"unknown-chmod-retry", func(m *pathLifecycleModel, _ *PathLifecycleOptions) {
			m.failures["capture"] = failure
			m.failures["open"] = os.ErrPermission
			m.retryMode = true
		}, -1, ErrPathLifecycleUndefined, false},
		{"known-chmod-retry", func(m *pathLifecycleModel, _ *PathLifecycleOptions) {
			m.failures["open"] = os.ErrPermission
			m.retryMode = true
		}, -1, os.ErrPermission, false},
		{"capture-failure-with-stat", func(m *pathLifecycleModel, o *PathLifecycleOptions) { m.failures["capture"] = failure; o.Stat = true }, 0, nil, true},
		{"no-follow-link", func(m *pathLifecycleModel, _ *PathLifecycleOptions) { m.original.NoFollowLink = true }, 0, nil, true},
		{"same", func(m *pathLifecycleModel, _ *PathLifecycleOptions) { m.same = true }, 0, nil, false},
		{"same-exclusive", func(m *pathLifecycleModel, o *PathLifecycleOptions) { m.same = true; o.Exclusive = true }, -1, os.ErrExist, false},
		{"same-probe-error", func(m *pathLifecycleModel, _ *PathLifecycleOptions) { m.same = true; m.failures["same"] = failure }, 0, nil, true},
		{"real-user-error", func(m *pathLifecycleModel, _ *PathLifecycleOptions) {
			m.original.Properties.RawSecurity = &appledouble.FileSecurity{ACL: &appledouble.ACL{}}
			m.failures["real-user"] = failure
		}, 0, nil, true},
		{"invalid-filesec", func(m *pathLifecycleModel, _ *PathLifecycleOptions) { m.original.Properties.RemoveACL = true }, 0, nil, true},
		{"full-acl", func(m *pathLifecycleModel, _ *PathLifecycleOptions) {
			m.original.Properties.RawSecurity = &appledouble.FileSecurity{ACL: &appledouble.ACL{Entries: make([]appledouble.ACLEntry, 128)}}
		}, 0, nil, true},
		{"positive-route", func(m *pathLifecycleModel, _ *PathLifecycleOptions) { m.route = CopyStageResult{Code: 3, Err: failure} }, 3, nil, true},
		{"negative-other-route", func(m *pathLifecycleModel, _ *PathLifecycleOptions) {
			m.route = CopyStageResult{Code: -2, Err: failure}
		}, -2, failure, true},
		{"route-without-error", func(m *pathLifecycleModel, _ *PathLifecycleOptions) { m.route.Code = -1 }, -1, nil, false},
		{"move-failure", func(m *pathLifecycleModel, o *PathLifecycleOptions) {
			o.MoveSource = true
			m.failures["remove-source"] = failure
		}, 0, nil, true},
		{"cache-failure", func(m *pathLifecycleModel, _ *PathLifecycleOptions) {
			m.failures["source-cache"], m.failures["destination-cache"] = failure, failure
		}, 0, nil, true},
		{"reset-failure", func(m *pathLifecycleModel, _ *PathLifecycleOptions) { m.failures["reset"] = failure }, 0, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newPathLifecycleModel()
			o := pathOptions()
			tc.configure(m, &o)
			r, e := CopyPathMetadata(context.Background(), o, m)
			if r.Code != tc.code || r.Completed != (tc.code >= 0) || (tc.match != nil && !errors.Is(e, tc.match)) || (tc.code >= 0 && e != nil) {
				t.Fatal(r, e, m.steps)
			}
			reset := false
			for _, step := range m.steps {
				reset = reset || step == "reset"
			}
			if reset != tc.wantReset || m.opened {
				t.Fatal("cleanup", m.steps)
			}
			if tc.code < 0 && e == nil {
				t.Fatal("failure lacks error", r)
			}
		})
	}
}

func TestPathLifecycleValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := newPathLifecycleModel()
	for _, tc := range []struct {
		ctx  context.Context
		o    PathLifecycleOptions
		b    PathLifecycleBackend
		want error
	}{
		{nil, pathOptions(), m, os.ErrInvalid}, {context.Background(), PathLifecycleOptions{}, m, os.ErrInvalid}, {context.Background(), pathOptions(), nil, os.ErrInvalid}, {ctx, pathOptions(), m, context.Canceled},
	} {
		if _, e := CopyPathMetadata(tc.ctx, tc.o, tc.b); !errors.Is(e, tc.want) {
			t.Fatal(e)
		}
	}
	if len(m.steps) != 0 {
		t.Fatal("validation had side effects", m.steps)
	}
}

func TestPathLifecycleModernFailureDiagnostics(t *testing.T) {
	primary, cleanup := errors.New("native route"), errors.New("failed destination unlink")
	m := newPathLifecycleModel()
	m.route = CopyStageResult{Code: -1, Err: primary}
	m.routeSteps = []HeldLifecycleStep{{Operation: "remove-destination", Err: cleanup}}
	result, err := CopyPathMetadata(context.Background(), pathOptions(), m)
	if result.Code != -1 || !errors.Is(err, primary) || !errors.Is(err, cleanup) {
		t.Fatal(result, err)
	}
	m = newPathLifecycleModel()
	m.failures["validate"] = primary
	result, err = CopyPathMetadata(context.Background(), pathOptions(), m)
	if result.Code != -1 || !errors.Is(err, primary) || m.mode != 0400 || strings.Contains(strings.Join(m.steps, " "), "route") {
		t.Fatal(result, err, m.steps)
	}
	for _, failed := range []bool{false, true} {
		m = newPathLifecycleModel()
		m.temporaryClose = []HeldLifecycleStep{{Operation: "close-temporary-security", Err: cleanup}}
		if failed {
			m.route = CopyStageResult{Code: -1, Err: primary}
		}
		result, err = CopyPathMetadata(context.Background(), pathOptions(), m)
		if !errors.Is(err, cleanup) || result.Completed == failed {
			t.Fatal(result, err)
		}
		if failed && !errors.Is(err, primary) {
			t.Fatal(err)
		}
		joined := strings.Join(m.steps, " ")
		if !failed && !strings.Contains(joined, "held-mode close-temporary reset") {
			t.Fatal(joined)
		}
		if failed && !strings.Contains(joined, "path-mode close-temporary close-source") {
			t.Fatal(joined)
		}
	}
	m = newPathLifecycleModel()
	options := pathOptions()
	options.UnlinkDestination = true
	result, err = CopyPathMetadata(context.Background(), options, m)
	if err != nil || !result.Completed || m.prepared.Mode != nil {
		t.Fatal(result, err, m.prepared)
	}
}
