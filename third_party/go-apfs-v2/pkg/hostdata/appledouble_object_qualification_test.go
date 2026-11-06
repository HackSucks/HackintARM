package hostdata

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestAppleDoubleObjectAcquisitionOrder(t *testing.T) {
	for fail := 0; fail <= 5; fail++ {
		t.Run(string(rune('0'+fail)), func(t *testing.T) {
			marker := errors.New("capture failed")
			calls := 0
			step := func() error {
				calls++
				if calls == fail {
					return marker
				}
				return nil
			}
			logical := objectFixture(t)
			p := objectCaptureProviders{
				metadata:   func(*os.File) (objectMetadata, error) { return logical.meta, step() },
				identities: func(context.Context) (*appledouble.ACLIdentityCapture, error) { return logical.identities, step() },
				process:    func(context.Context) (*QuarantineProcessCapture, error) { return &logical.process, step() },
				sandbox:    func() (bool, error) { return true, step() },
				attributes: func(*os.File) (objectAttributes, error) { return logical.attrs, step() },
			}
			got, err := newHostAppleDoubleObject(context.Background(), nil, p)
			if fail == 0 {
				if err != nil || got == nil || !got.sandboxed || calls != 5 {
					t.Fatal(got, err, calls)
				}
			} else if !errors.Is(err, marker) || got != nil || calls != fail {
				t.Fatal(got, err, calls)
			}
		})
	}
	c := CapturedAppleDoubleObject{State: logicalMetadataFixture(t).Snapshot(), Process: QuarantineProcessCapture{Profile: appledouble.QuarantineMacOS26, Absent: true}}
	if _, err := NewCapturedAppleDoubleObject(c); !errors.Is(err, appledouble.ErrACLIdentitySnapshot) {
		t.Fatal(err)
	}
	c.Identities.Version = 1
	c.Attributes = []appledouble.StreamAttr{objectAttr("", "")}
	if _, err := NewCapturedAppleDoubleObject(c); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
}

type objectFailedStat struct {
	objectMetadata
	err error
}

func (m objectFailedStat) CaptureStat() (StatCopySource, error) { return StatCopySource{}, m.err }
func TestAppleDoubleObjectCacheAndStatFailure(t *testing.T) {
	marker := errors.New("stat failed")
	o := objectFixture(t)
	old := StatCopySource{UID: 42}
	o.stat = old
	o.meta = objectFailedStat{o.meta, marker}
	if _, err := o.CaptureStat(); !errors.Is(err, marker) || o.stat != old {
		t.Fatal(err, o.stat)
	}
	if _, _, err := o.LogicalSnapshot(); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal(err)
	}
	prior := &SecurityCopySource{UID: 1}
	current := &SecurityCopySource{UID: 2}
	held := &HeldMetadata{SourceCache: prior}
	o.meta = held
	reset := o.sourceCache(current)
	if held.SourceCache != current {
		t.Fatal("held cache not installed")
	}
	reset()
	if held.SourceCache != prior {
		t.Fatal("held cache not restored")
	}
	o.meta = objectFailedStat{objectFixture(t).meta, nil}
	defer func() {
		if recover() == nil {
			t.Fatal("unregistered metadata accepted")
		}
	}()
	o.sourceCache(current)
}

func TestAppleDoubleObjectBackendACLAndIntent(t *testing.T) {
	source, target := objectFixture(t), objectFixture(t)
	backend := objectPackBackend{source: source, destination: target, result: &ObjectPackResult{}}
	if present, err := backend.ACLPresent(); present || err != nil {
		t.Fatal(present, err)
	}
	if _, err := backend.ACL(); !errors.Is(err, appledouble.ErrFileSecurity) {
		t.Fatal(err)
	}
	backend.security.Properties.RawSecurity = &appledouble.FileSecurity{}
	if _, err := backend.ACLPresent(); !errors.Is(err, appledouble.ErrFileSecurity) {
		t.Fatal(err)
	}
	acl := &appledouble.ACL{Entries: []appledouble.ACLEntry{{Principal: [16]byte{1}, Flags: 1, Rights: 2}}}
	backend.security.Properties.RawSecurity.ACL = acl
	if present, err := backend.ACLPresent(); !present || err != nil {
		t.Fatal(present, err)
	}
	if _, err := backend.ACL(); !errors.Is(err, appledouble.ErrACLIdentityUncaptured) {
		t.Fatal(err)
	}
	source.identities = appledouble.NewACLIdentityCapture(func(appledouble.ACLIdentity) ([16]byte, error) {
		return [16]byte{}, appledouble.ErrACLIdentityUncaptured
	}, func([16]byte) (appledouble.ACLPrincipal, bool, error) { return appledouble.ACLPrincipal{}, false, nil })
	text, err := backend.ACL()
	if err != nil || !bytes.HasSuffix(text, []byte{0}) {
		t.Fatal(err, text)
	}
	if backend.PreserveForIntent("user.example#N", 1) || !backend.PreserveForIntent("user.example#S", 4) {
		t.Fatal("intent policy")
	}
	source.CaptureStat()
	target.CaptureStat()
	if got := backend.Stat(); got.Code != 0 || got.Err != nil {
		t.Fatal(got)
	}
	source.CaptureStat()
	target.CaptureStat()
	backend.quarantine = &appledouble.Quarantine{Flags: 1, Agent: "Fixture"}
	if q, err := backend.Quarantine(); err != nil || !bytes.HasPrefix(q, []byte("q/")) {
		t.Fatal(err)
	}
	u := objectUnpackBackend{ctx: context.Background(), source: source, destination: target, options: DefaultObjectUnpackOptions(), result: &ObjectUnpackResult{}}
	for _, capacity := range []int{-1, int(MaxXattrListSize) + 1} {
		if _, err := u.XattrNames(capacity); !errors.Is(err, ErrUnpackListAllocation) {
			t.Fatal(err)
		}
	}
	if got := u.ACL([]byte("!#acl 1\nuser::uncaptured::allow:read\n")); got.Code != -1 || !errors.Is(got.Err, appledouble.ErrACLIdentityUncaptured) {
		t.Fatal(got)
	}
	if got := u.ACL(text); got.Code != 0 || got.Err != nil || !u.result.ACL.Applied {
		t.Fatal(got, u.result.ACL)
	}
	gotACL, _ := target.meta.CaptureDestinationACL()
	if !reflect.DeepEqual(gotACL, acl) {
		t.Fatal(gotACL)
	}
	if got := u.Stat(true); got.Code != 0 || got.Err != nil {
		t.Fatal(got)
	}
}

type objectApplyFailure struct {
	objectAttributes
	err error
}

func (a objectApplyFailure) applyQuarantine(context.Context, *appledouble.Quarantine, QuarantineProcessCapture, uint32) error {
	return a.err
}
func TestAppleDoubleObjectQuarantinePolicy(t *testing.T) {
	ctx := context.Background()
	source, target := objectFixture(t), objectFixture(t)
	options := DefaultObjectUnpackOptions()
	options.Timestamp = func() time.Time { return time.Unix(123, 0) }
	backend := objectUnpackBackend{ctx: ctx, source: source, destination: target, options: options, result: &ObjectUnpackResult{}, copied: 99}
	if got := backend.Quarantine([]byte("invalid")); got.Code != 0 || !errors.Is(got.Err, appledouble.ErrQuarantine) {
		t.Fatal(got)
	}
	wire := []byte("q/0001;00000001;WireAgent;ID\x00")
	if got := backend.Quarantine(wire); got.Code != 0 || got.Err != nil {
		t.Fatal(got)
	}
	backend.quarantine = &appledouble.Quarantine{Flags: 1, Timestamp: 2, Agent: "SourceAgent", Identifier: "ID"}
	if got := backend.Quarantine([]byte("invalid")); got.Code != 0 || got.Err != nil {
		t.Fatal(got)
	}
	_, attrs, err := target.LogicalSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(attrs) != 1 {
		t.Fatal(attrs)
	}
	q, err := target.attrs.quarantine(ctx, target.process.Profile)
	if err != nil || q.Agent != "SourceAgent" {
		t.Fatal(q, err)
	}
	original := target.attrs
	for _, test := range []struct {
		err  error
		code int
	}{{syscall.EACCES, int(syscall.EACCES)}, {appledouble.ErrQuarantineMissing, 93}, {appledouble.ErrQuarantineExisting, 22}, {io.ErrClosedPipe, 45}} {
		target.attrs = objectApplyFailure{original, test.err}
		backend.options.Callback = nil
		if got := backend.Quarantine(wire); got.Code != test.code || !errors.Is(got.Err, test.err) {
			t.Fatal(got)
		}
		for _, action := range []CopyPipelineAction{CopyPipelineContinue, CopyPipelineQuit} {
			backend.options.Callback = func(notice UnpackNotice) CopyPipelineAction {
				if notice.Copied != 99 || notice.Stage != UnpackQuarantine || !errors.Is(notice.WriteError, test.err) {
					t.Fatal(notice)
				}
				return action
			}
			got := backend.Quarantine(wire)
			want := 0
			if action == CopyPipelineQuit {
				want = test.code
			}
			if got.Code != want || !errors.Is(got.Err, test.err) {
				t.Fatal(got)
			}
		}
	}
}

func TestAppleDoubleObjectLogicalQuarantine(t *testing.T) {
	ctx := context.Background()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	q := &appledouble.Quarantine{Flags: 1, Timestamp: 2, Agent: "Source", Identifier: "ID"}
	for _, kind := range []uint32{0100000, 0040000, 0120000} {
		o := objectFixture(t)
		a := o.attrs.(*logicalObjectAttributes)
		a.meta.state.Stat.Mode = kind | 0600
		if err := a.applyQuarantine(ctx, q, o.process, 123); err != nil {
			t.Fatal(err)
		}
		if got, err := a.quarantine(ctx, o.process.Profile); err != nil || got.Agent != "Source" {
			t.Fatal(got, err)
		}
		if _, err := a.quarantine(cancelled, o.process.Profile); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if err := a.applyQuarantine(cancelled, q, o.process, 123); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if err := a.applyQuarantine(ctx, q, QuarantineProcessCapture{Profile: 99}, 123); !errors.Is(err, appledouble.ErrQuarantineContext) {
			t.Fatal(err)
		}
		a.values[appledouble.QuarantineName] = objectBrokenValue{size: appledouble.MaxQuarantineXattrSize + 1}
		if _, err := a.quarantineBytes(); !errors.Is(err, appledouble.ErrQuarantine) {
			t.Fatal(err)
		}
		if err := a.applyQuarantine(ctx, q, o.process, 123); !errors.Is(err, appledouble.ErrQuarantine) {
			t.Fatal(err)
		}
		a.values[appledouble.QuarantineName] = objectBrokenValue{size: 2, err: io.ErrClosedPipe}
		if _, err := a.quarantineBytes(); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(err)
		}
		delete(a.values, appledouble.QuarantineName)
		unsupported := QuarantineProcessCapture{Profile: appledouble.QuarantineMacOS26, Flags: 0xffffffff}
		if err := a.applyQuarantine(ctx, q, unsupported, 123); !errors.Is(err, appledouble.ErrQuarantineContext) {
			t.Fatal(err)
		}
		if err := a.applyQuarantine(ctx, &appledouble.Quarantine{Flags: 0x200}, QuarantineProcessCapture{Profile: appledouble.QuarantineMacOS27, Flags: 0x200, Agent: []byte("ContextAgent")}, 123); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAppleDoubleObjectForkPrefixRetention(t *testing.T) {
	a, err := newLogicalObjectAttributes(logicalMetadataFixture(t), []appledouble.StreamAttr{objectAttr(appledouble.ResourceForkName, "original fork data")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	original := a.values[appledouble.ResourceForkName]
	expected := []byte("original fork data")
	var prior []appledouble.Value
	var priorData [][]byte
	for _, value := range []string{"four", "AB", "XYZ", "z", "longest", "short", "a"} {
		prior = append(prior, a.values[appledouble.ResourceForkName])
		priorData = append(priorData, bytes.Clone(expected))
		if err := a.write(appledouble.ResourceForkName, []byte(value)); err != nil {
			t.Fatal(err)
		}
		copy(expected, value)
		current := a.values[appledouble.ResourceForkName].(*prefixObjectValue)
		if current.tail != original {
			t.Fatal("retained a superseded prefix overlay")
		}
		got := make([]byte, current.Size())
		if _, err := current.ReadAt(got, 0); err != nil || !bytes.Equal(got, expected) {
			t.Fatal(string(got), err)
		}
	}
	for i, v := range prior {
		got := make([]byte, v.Size())
		if _, err := v.ReadAt(got, 0); err != nil || !bytes.Equal(got, priorData[i]) {
			t.Fatal("old snapshot mutated", i, err)
		}
	}
	// An unreadable enormous borrowed suffix proves coalescing performs no
	// whole-fork allocation or IO. Only the small written prefix is owned.
	huge := objectBrokenValue{size: 1 << 40, err: io.ErrClosedPipe}
	a.values[appledouble.ResourceForkName] = huge
	for i := 0; i < 100; i++ {
		if err := a.write(appledouble.ResourceForkName, bytes.Repeat([]byte{byte(i)}, 1+i%9)); err != nil {
			t.Fatal(err)
		}
	}
	current := a.values[appledouble.ResourceForkName].(*prefixObjectValue)
	if current.Size() != 1<<40 || len(current.head) != 9 || current.tail != huge {
		t.Fatal("borrowed suffix retention changed")
	}
}
