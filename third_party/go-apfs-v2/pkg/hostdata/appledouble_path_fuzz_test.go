package hostdata

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

// Instrument the production binding, not a second lifecycle implementation.
// Real descriptors and real pack/unpack effects remain in use on every OS.
// Only acquisition outcomes and cancellation timing are controlled boundaries.
type fuzzPathBinding struct {
	*appleDoublePath
	cancel     context.CancelFunc
	cancelAt   byte
	events     []string
	insideOpen bool
	closeCalls int
	closeFault error
}

func (b *fuzzPathBinding) point(name string, phase byte) {
	b.events = append(b.events, name)
	if b.cancelAt == phase {
		b.cancel()
	}
}
func (b *fuzzPathBinding) CaptureDestination() (PathDestinationState, error) {
	s, e := b.appleDoublePath.CaptureDestination()
	b.point("capture", 1)
	return s, e
}
func (b *fuzzPathBinding) ApplyTemporarySecurity(p aclmeta.DarwinChmodProperties) error {
	e := b.appleDoublePath.ApplyTemporarySecurity(p)
	b.point("temporary", 2)
	return e
}
func (b *fuzzPathBinding) Open(ctx context.Context, limit uint64) (PathOpenResult, error) {
	b.insideOpen = true
	r, e := b.appleDoublePath.Open(ctx, limit)
	b.insideOpen = false
	b.point("open", 3)
	return r, e
}
func (b *fuzzPathBinding) ValidateDestination() error {
	e := b.appleDoublePath.ValidateDestination()
	b.point("validate", 4)
	return e
}
func (b *fuzzPathBinding) ConfigureIO() []HeldLifecycleStep {
	r := b.appleDoublePath.ConfigureIO()
	b.point("configure", 5)
	return r
}
func (b *fuzzPathBinding) Run(ctx context.Context) (CopyStageResult, []HeldLifecycleStep) {
	r, s := b.appleDoublePath.Run(ctx)
	b.point("route", 6)
	return r, s
}
func (b *fuzzPathBinding) RestoreBSD(s StatCopySource, failure bool) []HeldLifecycleStep {
	b.events = append(b.events, "restore")
	return b.appleDoublePath.RestoreBSD(s, failure)
}
func (b *fuzzPathBinding) CloseTemporarySecurity() []HeldLifecycleStep {
	b.events = append(b.events, "close-temporary")
	return b.appleDoublePath.CloseTemporarySecurity()
}
func (b *fuzzPathBinding) ResetSecurity() []HeldLifecycleStep {
	b.events = append(b.events, "reset")
	return b.appleDoublePath.ResetSecurity()
}
func (b *fuzzPathBinding) RemoveSource() error {
	b.events = append(b.events, "remove-source")
	return b.appleDoublePath.RemoveSource()
}
func (b *fuzzPathBinding) Close() []HeldLifecycleStep {
	b.closeCalls++
	b.events = append(b.events, "close")
	steps := b.appleDoublePath.Close()
	if b.closeFault != nil {
		steps = append(steps, HeldLifecycleStep{Operation: "controlled-close-failure", Err: b.closeFault})
	}
	return steps
}

func FuzzPathLifecycle(f *testing.F) {
	for _, seed := range [][]byte{
		{0, 0, 0, 5, 0, 0, 0, 0}, {1, 0, 0, 5, 0, 0, 0, 0},
		{0, 0, 7, 1, 0, 0, 0, 0}, {1, 0, 7, 1, 1, 0, 0, 0},
		{0, 0, 0, 5, 0, 1, 0, 0}, {1, 0, 0, 5, 0, 1, 0, 0},
		{0, 0, 0, 5, 0, 0, 1, 0}, {1, 0, 0, 5, 0, 0, 1, 0},
		{0, 0, 0, 5, 0, 0, 0, 1}, {0, 0, 0, 5, 0, 0, 0, 2},
	} {
		f.Add(seed)
	}
	for stage := byte(1); stage <= 6; stage++ {
		f.Add([]byte{0, stage, 0, 5, 0, 0, 0, 0})
		f.Add([]byte{1, stage, 0, 5, 0, 0, 0, 0})
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		var control [8]byte
		copy(control[:], input)
		var value []byte
		if len(input) > 8 {
			value = bytes.Clone(input[8:min(len(input), 72)])
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		dir := t.TempDir()
		name, target := filepath.Join(dir, "source"), filepath.Join(dir, "destination")
		source := objectFixture(t, appledouble.StreamAttr{Name: "user.fuzz", Value: bytes.NewReader(value)})
		destination := objectFixture(t, objectAttr("user.old", "old metadata"))
		if err := destination.Chmod(0400); err != nil {
			t.Fatal(err)
		}
		original, err := destination.CaptureStat()
		if err != nil {
			t.Fatal(err)
		}
		options := AppleDoublePathOptions{Operation: PathPackAppleDouble, Pack: DefaultObjectPackOptions(), Unpack: DefaultObjectUnpackOptions(), MaxOpenAttempts: uint64(control[3]%6) + 1, Captured: pathCapturedFixture(t, source, destination)}
		options.Pack.Stat = control[4]&2 != 0
		options.Unpack.Stat = options.Pack.Stat
		options.Exclusive = control[4]&4 != 0
		options.MoveSource = control[4]&8 != 0
		options.UnlinkDestination = control[4]&16 != 0
		body := []byte("source data")
		if control[0]&1 != 0 {
			options.Operation = PathUnpackAppleDouble
			wire := appledouble.StreamFile{Attrs: []appledouble.StreamAttr{{Name: "user.new", Value: bytes.NewReader(append([]byte("new metadata"), value...))}}}
			var encoded bytes.Buffer
			if _, err := wire.EncodeTo(ctx, &encoded, appledouble.DefaultStreamLimits()); err != nil {
				t.Fatal(err)
			}
			body = encoded.Bytes()
			if control[5]&1 != 0 {
				body = body[:len(body)-1]
			}
		} else if control[5]&1 != 0 {
			broken := errors.New("controlled value read failure")
			source.attrs.(*logicalObjectAttributes).values["user.fuzz"] = objectBrokenValue{size: 8, err: broken}
		}
		if err := os.WriteFile(name, body, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte("destination data"), 0600); err != nil {
			t.Fatal(err)
		}
		if control[4]&32 != 0 {
			if err := os.Chmod(target, 0444); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(target, 0600) })
		}
		physicalBefore, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		p := &appleDoublePath{ctx: ctx, sourceName: name, destinationName: target, options: options, result: &AppleDoublePathResult{}, native: defaultPathNativeOps(), access: defaultPathAccessOps()}
		defer p.Close()
		b := &fuzzPathBinding{appleDoublePath: p, cancel: cancel, cancelAt: control[1] % 8}
		if control[6]&1 != 0 {
			b.closeFault = errors.New("controlled cleanup failure")
		}
		var acquired []*os.File
		attempts := uint64(0)
		fault := errors.New("controlled endpoint acquisition failure")
		faultObserved := false
		open := p.access.open
		p.access.open = func(n string, flags int, mode uint32, nofollow, protected bool, class int) (*os.File, error) {
			if b.insideOpen {
				if n == name && control[7]%3 == 1 {
					faultObserved = true
					return nil, fault
				}
				if n == target {
					attempts++
					if control[7]%3 == 2 {
						faultObserved = true
						return nil, fault
					}
					if attempts <= uint64(control[2]%8) {
						if control[4]&1 != 0 {
							return nil, syscall.EISDIR
						}
						return nil, os.ErrExist
					}
				}
			}
			file, err := open(n, flags, mode, nofollow, protected, class)
			if file != nil {
				acquired = append(acquired, file)
			}
			return file, err
		}
		if b.cancelAt == 7 {
			cancel()
		}
		result, err := CopyPathMetadata(ctx, PathLifecycleOptions{Stat: options.Pack.Stat, Exclusive: options.Exclusive, MoveSource: options.MoveSource, UnlinkDestination: options.UnlinkDestination, MaxOpenAttempts: options.MaxOpenAttempts}, b)
		if attempts > options.MaxOpenAttempts || len(result.Steps) > 100+int(options.MaxOpenAttempts)*3 {
			t.Fatalf("unbounded work: attempts=%d result=%+v", attempts, result)
		}
		wantClose := 1
		if b.cancelAt == 7 {
			wantClose = 0
		}
		if b.closeCalls != wantClose {
			t.Fatalf("outer release count=%d want=%d", b.closeCalls, wantClose)
		}
		closed := map[string]bool{}
		for _, step := range result.Steps {
			if strings.HasPrefix(step.Operation, "close-") {
				if closed[step.Operation] || errors.Is(step.Err, os.ErrClosed) {
					t.Fatal("descriptor closed twice", step, result.Steps)
				}
				closed[step.Operation] = true
			}
		}
		for _, file := range acquired {
			if _, e := file.Read(make([]byte, 1)); !errors.Is(e, os.ErrClosed) {
				t.Fatalf("acquired descriptor escaped cleanup: %s %v", file.Name(), e)
			}
		}
		if steps := p.Close(); len(steps) != 0 {
			t.Fatal("release was not idempotent", steps)
		}
		if faultObserved && !errors.Is(err, fault) {
			t.Fatal("primary acquisition error lost", err)
		}
		if b.closeFault != nil && b.closeCalls != 0 && !errors.Is(err, b.closeFault) {
			t.Fatal("cleanup error lost", err)
		}
		if ctx.Err() != nil {
			if err == nil || result.Completed || slices.Contains(b.events, "reset") || slices.Contains(b.events, "remove-source") {
				t.Fatal("success cleanup after cancellation", result, err, b.events)
			}
		}
		if result.Code == -1 && result.PermissionsChanged && result.DestinationKnown && !result.DestinationCreated {
			restore, closeTemporary := slices.Index(b.events, "restore"), slices.Index(b.events, "close-temporary")
			if restore < 0 || closeTemporary <= restore {
				t.Fatal("failed-operation restore did not precede temporary release", b.events)
			}
			state, statErr := destination.CaptureStat()
			if statErr != nil || state.Mode != original.Mode {
				t.Fatal("temporary mode survived failure", state, original, statErr)
			}
		}
		if reset := slices.Index(b.events, "reset"); reset >= 0 {
			if closeTemporary := slices.Index(b.events, "close-temporary"); closeTemporary < 0 || closeTemporary >= reset {
				t.Fatal("security reset preceded temporary release", b.events)
			}
		}
		if result.Code == -1 && (slices.Contains(b.events, "reset") || slices.Contains(b.events, "remove-source")) {
			t.Fatal("failed route ran success cleanup", b.events)
		}
		if !options.UnlinkDestination {
			physicalAfter, statErr := os.Stat(target)
			if statErr == nil && physicalAfter.Mode().Perm() != physicalBefore.Mode().Perm() {
				t.Fatal("receiving-host temporary mode was not restored", physicalBefore.Mode(), physicalAfter.Mode())
			}
		}
		// Unpack mutates metadata only, even for malformed late input.
		if options.Operation == PathUnpackAppleDouble && !options.UnlinkDestination {
			data, readErr := os.ReadFile(target)
			if readErr != nil || string(data) != "destination data" {
				t.Fatal("unpack altered payload data", string(data), readErr)
			}
		}
	})
}
