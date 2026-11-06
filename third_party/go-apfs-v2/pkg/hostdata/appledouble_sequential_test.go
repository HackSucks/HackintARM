package hostdata_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/unpackrestore"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func TestUnpackSequentialExistingNative(t *testing.T) {
	for _, name := range []string{"unpack-restore.json.gz", "unpack-restore-ci.json.gz"} {
		t.Run(name, func(t *testing.T) {
			file, err := os.Open("../../testdata/appledouble/native/" + name)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			gz, err := gzip.NewReader(file)
			if err != nil {
				t.Fatal(err)
			}
			defer gz.Close()
			var fixture unpackrestore.Fixture
			if err := json.NewDecoder(gz).Decode(&fixture); err != nil {
				t.Fatal(err)
			}
			if len(fixture.Cases) != 1907 || len(fixture.Live) != 96 {
				t.Fatal("native cases missing")
			}
			for _, group := range [][]unpackrestore.Case{fixture.Cases, fixture.Live} {
				for i, c := range group {
					if err := unpackrestore.ReplaySequential(c, fixture.Images); err != nil {
						t.Fatalf("case %d: %v", i, err)
					}
				}
			}
		})
	}
}

func TestUnpackSequentialLateNative(t *testing.T) {
	file, err := os.Open("../../testdata/appledouble/native/unpack-sequential.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	var fixture unpackrestore.Fixture
	if err := json.NewDecoder(gz).Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fixture.Images, unpackrestore.SequentialImages()) || len(fixture.Cases) != 34 || len(fixture.Live) != 30 {
		t.Fatal("sequential native inputs changed")
	}
	helper, err := os.ReadFile("../../testdata/appledouble/native/unpack-restore.c")
	if err != nil {
		t.Fatal(err)
	}
	helper = bytes.ReplaceAll(helper, []byte("\r\n"), []byte("\n"))
	if fmt.Sprintf("%x", sha256.Sum256(helper)) != fixture.HelperSHA256 || fixture.CopyfileSHA256 != "19f3ad0910f05bb2a6ae982ebdabcc4dc9c911b65ec2d99e75b7c4c52272805c" {
		t.Fatal("sequential native source provenance")
	}
	for index, group := range [][]unpackrestore.Case{fixture.Cases, fixture.Live} {
		inputs := unpackrestore.SequentialCases(index == 1)
		for i, c := range group {
			spec := c
			spec.Native = unpackrestore.Observation{}
			if !reflect.DeepEqual(spec, inputs[i]) {
				t.Fatalf("changed native input %d", i)
			}
			if index == 1 && !c.Native.RemovedSeeds {
				t.Fatal("missing live cleanup readback")
			}
			if err := unpackrestore.ReplaySequential(c, fixture.Images); err != nil {
				t.Fatalf("case %d: %v", i, err)
			}
		}
	}
}

type sequentialBackend struct {
	events   []string
	values   map[string][]byte
	stat     hostdata.CopyStageResult
	forkErr  error
	writeErr error
	onWrite  func()
}

func (b *sequentialBackend) ListXattrSize() (int, error) {
	b.events = append(b.events, "list-size")
	return 6, nil
}
func (b *sequentialBackend) XattrNames(int) ([]string, error) {
	b.events = append(b.events, "list-names")
	return []string{"stale"}, nil
}
func (b *sequentialBackend) RemoveXattr(name string) error {
	b.events = append(b.events, "remove:"+name)
	delete(b.values, name)
	return nil
}
func (b *sequentialBackend) WriteXattr(name string, value []byte) error {
	b.events = append(b.events, "write:"+name)
	if b.writeErr != nil {
		return b.writeErr
	}
	b.values[name] = bytes.Clone(value)
	if b.onWrite != nil {
		b.onWrite()
	}
	return nil
}
func (b *sequentialBackend) CaptureForkState() (hostdata.UnpackForkState, error) {
	b.events = append(b.events, "fork-stat")
	return hostdata.UnpackForkState{}, b.forkErr
}
func (b *sequentialBackend) RestoreForkTimes(hostdata.UnpackForkState) error {
	b.events = append(b.events, "fork-times")
	return nil
}
func (b *sequentialBackend) Quarantine([]byte) hostdata.CopyStageResult {
	b.events = append(b.events, "quarantine")
	return hostdata.CopyStageResult{}
}
func (b *sequentialBackend) ACL([]byte) hostdata.CopyStageResult {
	b.events = append(b.events, "acl")
	return hostdata.CopyStageResult{}
}
func (b *sequentialBackend) Stat(bool) hostdata.CopyStageResult {
	b.events = append(b.events, "stat")
	return b.stat
}

func newSequentialBackend() *sequentialBackend {
	return &sequentialBackend{values: map[string][]byte{"stale": {1}}}
}

func sequentialOptions() hostdata.UnpackSequentialOptions {
	return hostdata.UnpackSequentialOptions{Limits: appledouble.DefaultStreamLimits(), MaxActiveBytes: 1 << 20}
}

func sequentialBytes(t *testing.T, f *appledouble.File) []byte {
	t.Helper()
	b, err := f.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUnpackSequentialPartialMutation(t *testing.T) {
	base := sequentialBytes(t, &appledouble.File{Attrs: []appledouble.Attr{{Name: "a", Value: []byte{1}}, {Name: "b", Value: []byte{2}}}})
	for _, mutation := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{"late-value", func(b []byte) []byte { return b[:len(b)-1] }},
		{"late-name", func(b []byte) []byte { b[146] = 1; return b }},
		{"finder", func(b []byte) []byte { binary.BigEndian.PutUint32(b[30:], math.MaxUint32); return b }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			input := mutation.edit(bytes.Clone(base))
			backend := newSequentialBackend()
			got, err := hostdata.RestoreAppleDoubleSequential(context.Background(), bytes.NewReader(input), sequentialOptions(), backend)
			if err == nil || got.Code != -1 || got.ReachedEnd || !bytes.Equal(backend.values["a"], []byte{1}) || backend.values["stale"] != nil || len(got.Failures) != 1 {
				t.Fatalf("partial effects missing: %+v %v values=%v", got, err, backend.values)
			}
			safe := newSequentialBackend()
			if _, err := hostdata.RestoreAppleDouble(input, hostdata.UnpackOptions{}, safe); err == nil || len(safe.events) != 0 || safe.values["stale"] == nil {
				t.Fatal("safe snapshot changed its prevalidation guarantee")
			}
		})
	}
}

func TestUnpackSequentialHeaderAndEntryBoundaries(t *testing.T) {
	base := sequentialBytes(t, &appledouble.File{Attrs: []appledouble.Attr{{Name: "a", Value: []byte{1}}}})
	for _, tc := range []struct {
		name   string
		edit   func([]byte) []byte
		cleans bool
	}{
		{"short-base", func(b []byte) []byte { return b[:81] }, false},
		{"magic", func(b []byte) []byte { b[0] = 1; return b }, false},
		{"entry-count", func(b []byte) []byte { b[25] = 3; return b }, false},
		{"finder-id", func(b []byte) []byte { b[29] = 2; return b }, false},
		{"short-attr", func(b []byte) []byte { return b[:82] }, true},
		{"attr-magic", func(b []byte) []byte { b[84] = 0; return b }, true},
		{"entry-overrun", func(b []byte) []byte { b[119] = 2; return b }, true},
		{"small-name", func(b []byte) []byte { b[130] = 0; return b }, true},
		{"large-name", func(b []byte) []byte { b[130] = 129; return b }, true},
		{"name-overrun", func(b []byte) []byte { b[130] = 127; return b }, true},
		{"unterminated", func(b []byte) []byte { b[132] = 1; return b }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := newSequentialBackend()
			_, err := hostdata.RestoreAppleDoubleSequential(context.Background(), bytes.NewReader(tc.edit(bytes.Clone(base))), sequentialOptions(), backend)
			if err == nil || (backend.values["stale"] == nil) != tc.cleans {
				t.Fatalf("wrong error/effects: %v %+v", err, backend)
			}
		})
	}
	// Finder-only header and unknown second entry are accepted without ATTR reads.
	input := bytes.Clone(base[:82])
	binary.BigEndian.PutUint32(input[34:], 32)
	binary.BigEndian.PutUint32(input[38:], 99)
	if r, err := hostdata.RestoreAppleDoubleSequential(context.Background(), bytes.NewReader(input), sequentialOptions(), newSequentialBackend()); err != nil || !r.ReachedEnd {
		t.Fatalf("finder only: %+v %v", r, err)
	}
}

func TestUnpackSequentialForkReadMaskingAndAllocation(t *testing.T) {
	base := sequentialBytes(t, &appledouble.File{Attrs: []appledouble.Attr{{Name: appledouble.ACLTextName, Value: []byte("acl")}}, ResourceFork: []byte{7, 8, 9}})
	for _, stat := range []bool{false, true} {
		backend := newSequentialBackend()
		options := sequentialOptions()
		options.Stat = stat
		got, err := hostdata.RestoreAppleDoubleSequential(context.Background(), bytes.NewReader(base[:len(base)-1]), options, backend)
		want := []string{"list-size", "list-names", "remove:stale", "fork-stat", "acl"}
		if stat {
			want = append(want, "stat")
		}
		if err != nil || got.Code != 0 || !got.ReachedEnd || len(got.Failures) != 1 || got.Failures[0].Operation != "source-fork" || !reflect.DeepEqual(backend.events, want) {
			t.Fatalf("masked late fork: %+v %v events=%v", got, err, backend.events)
		}
	}
	base = sequentialBytes(t, &appledouble.File{ResourceFork: []byte{7, 8, 9}})
	backend := newSequentialBackend()
	got, err := hostdata.RestoreAppleDoubleSequential(context.Background(), bytes.NewReader(base[:len(base)-1]), sequentialOptions(), backend)
	if !errors.Is(err, io.ErrUnexpectedEOF) || got.Code != -1 || !got.ReachedEnd || len(got.Failures) != 1 {
		t.Fatalf("unmasked late fork: %+v %v", got, err)
	}
	options := sequentialOptions()
	options.MaxActiveBytes = uint64(len(base)) + 5 // Header fits; two fork buffers don't.
	backend = newSequentialBackend()
	got, err = hostdata.RestoreAppleDoubleSequential(context.Background(), bytes.NewReader(base), options, backend)
	if !errors.Is(err, hostdata.ErrUnpackValueAllocation) || len(got.Failures) != 1 || got.Failures[0].Operation != "fork-allocation" || !reflect.DeepEqual(backend.events, []string{"list-size", "list-names", "remove:stale"}) {
		t.Fatalf("fork budget order: %+v %v %v", got, err, backend.events)
	}
}

func TestUnpackSequentialBudgets(t *testing.T) {
	base := sequentialBytes(t, &appledouble.File{Attrs: []appledouble.Attr{{Name: "a", Value: []byte{1}}, {Name: "b", Value: []byte{2}}}})
	for _, tc := range []struct {
		name string
		edit func(*hostdata.UnpackSequentialOptions)
	}{
		{"file", func(o *hostdata.UnpackSequentialOptions) { o.Limits.MaxFileBytes = uint64(len(base) - 1) }},
		{"header", func(o *hostdata.UnpackSequentialOptions) { o.MaxActiveBytes = uint64(len(base) - 1) }},
		{"value", func(o *hostdata.UnpackSequentialOptions) { o.Limits.MaxValueBytes = 0 }},
		{"total", func(o *hostdata.UnpackSequentialOptions) { o.Limits.MaxTotalValueBytes = 1 }},
		{"active", func(o *hostdata.UnpackSequentialOptions) { o.MaxActiveBytes = uint64(len(base) + 1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := sequentialOptions()
			tc.edit(&o)
			backend := newSequentialBackend()
			_, err := hostdata.RestoreAppleDoubleSequential(context.Background(), bytes.NewReader(base), o, backend)
			if !errors.Is(err, appledouble.ErrStreamBudget) {
				t.Fatal(err)
			}
			if tc.name == "total" && !bytes.Equal(backend.values["a"], []byte{1}) {
				t.Fatal("late total budget discarded earlier write")
			}
		})
	}
	// Deferred ACL remains live while the next value and callback copy exist.
	base = sequentialBytes(t, &appledouble.File{Attrs: []appledouble.Attr{{Name: appledouble.ACLTextName, Value: []byte("1234")}, {Name: "z", Value: []byte("1234")}}})
	options := sequentialOptions()
	options.MaxActiveBytes = uint64(len(base)) + 8
	backend := newSequentialBackend()
	_, err := hostdata.RestoreAppleDoubleSequential(context.Background(), bytes.NewReader(base), options, backend)
	if !errors.Is(err, hostdata.ErrUnpackValueAllocation) || backend.values["z"] != nil {
		t.Fatalf("deferred ACL budget %v", err)
	}
}

type sequentialValue struct {
	size int64
	read func([]byte, int64) (int, error)
}

func (s sequentialValue) Size() int64 { return s.size }
func (s sequentialValue) ReadAt(b []byte, off int64) (int, error) {
	return s.read(b, off)
}

func TestUnpackSequentialSourceFailuresAndCancel(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int
		err  error
	}{
		{"negative", -1, nil}, {"excess", 121, nil}, {"short", 1, nil},
		{"eof", 1, io.EOF}, {"error", 1, os.ErrPermission}, {"full-error", 120, os.ErrPermission},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := newSequentialBackend()
			source := sequentialValue{size: 120, read: func([]byte, int64) (int, error) { return tc.n, tc.err }}
			if _, err := hostdata.RestoreAppleDoubleSequential(context.Background(), source, sequentialOptions(), backend); err == nil || len(backend.events) != 0 {
				t.Fatalf("header read failure mutated destination: %v", err)
			}
		})
	}
	for _, source := range []appledouble.Value{nil, sequentialValue{size: -1}, bytes.NewReader(nil)} {
		if _, err := hostdata.RestoreAppleDoubleSequential(context.Background(), source, sequentialOptions(), newSequentialBackend()); err == nil {
			t.Fatal("invalid source accepted")
		}
	}
	base := sequentialBytes(t, &appledouble.File{Attrs: []appledouble.Attr{{Name: "a", Value: []byte{1}}}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		if _, err := hostdata.RestoreAppleDoubleSequential(ctx, bytes.NewReader(base), sequentialOptions(), newSequentialBackend()); err == nil {
			t.Fatal("invalid context accepted")
		}
	}
	if _, err := hostdata.RestoreAppleDoubleSequential(context.Background(), bytes.NewReader(base), sequentialOptions(), nil); err == nil {
		t.Fatal("nil backend accepted")
	}
	ctx, cancel = context.WithCancel(context.Background())
	backend := newSequentialBackend()
	backend.onWrite = cancel
	got, err := hostdata.RestoreAppleDoubleSequential(ctx, bytes.NewReader(base), sequentialOptions(), backend)
	if !errors.Is(err, context.Canceled) || got.Code != -1 || backend.values["a"] == nil {
		t.Fatalf("late cancellation: %+v %v", got, err)
	}
	// ReaderAt may legally return complete bytes alongside EOF.
	source := sequentialValue{size: int64(len(base)), read: func(b []byte, off int64) (int, error) {
		n, _ := bytes.NewReader(base).ReadAt(b, off)
		return n, io.EOF
	}}
	if _, err := hostdata.RestoreAppleDoubleSequential(context.Background(), source, sequentialOptions(), newSequentialBackend()); err != nil {
		t.Fatal(err)
	}
}

func TestUnpackSequentialNameRefusalAfterStart(t *testing.T) {
	base := sequentialBytes(t, &appledouble.File{Attrs: []appledouble.Attr{{Name: "a"}}})
	for _, first := range []byte{0, 255} {
		input := bytes.Clone(base)
		input[131] = first
		backend := newSequentialBackend()
		backend.writeErr = os.ErrInvalid
		options := sequentialOptions()
		var notices []string
		options.Callback = func(n hostdata.UnpackNotice) hostdata.CopyPipelineAction {
			notices = append(notices, string(n.Event))
			return hostdata.CopyPipelineContinue
		}
		got, err := hostdata.RestoreAppleDoubleSequential(context.Background(), bytes.NewReader(input), options, backend)
		if err != nil || !got.ReachedEnd || len(got.Failures) != 1 || !reflect.DeepEqual(notices, []string{"start", "error"}) {
			t.Fatalf("native malformed-name callback order: %+v %v notices=%v", got, err, notices)
		}
	}
}

func TestUnpackSequentialReadBeforeIntent(t *testing.T) {
	base := sequentialBytes(t, &appledouble.File{Attrs: []appledouble.Attr{{Name: "filtered#N", Value: []byte{1}}}})
	if got, err := hostdata.RestoreAppleDoubleSequential(context.Background(), bytes.NewReader(base[:len(base)-1]), sequentialOptions(), newSequentialBackend()); err == nil || got.Code != -1 {
		t.Fatalf("filtered record skipped source read: %+v %v", got, err)
	}
	// A payload read failure is ordered after fork stat and before callback.
	base = sequentialBytes(t, &appledouble.File{ResourceFork: []byte{1}})
	backend := newSequentialBackend()
	var reads []int64
	source := sequentialValue{size: int64(len(base)), read: func(b []byte, off int64) (int, error) {
		reads = append(reads, off)
		if off != 0 {
			backend.events = append(backend.events, "fork-read")
			return 0, fmt.Errorf("fork failure: %w", os.ErrPermission)
		}
		return bytes.NewReader(base).ReadAt(b, off)
	}}
	_, err := hostdata.RestoreAppleDoubleSequential(context.Background(), source, sequentialOptions(), backend)
	if !errors.Is(err, os.ErrPermission) || len(reads) != 2 || !reflect.DeepEqual(backend.events, []string{"list-size", "list-names", "remove:stale", "fork-stat", "fork-read"}) {
		t.Fatalf("fork read order: %v %v", err, backend.events)
	}
}
