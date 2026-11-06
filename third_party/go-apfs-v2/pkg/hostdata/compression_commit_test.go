package hostdata

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/compression/decmpfs"
)

type compressionLifecycleEvent struct {
	Operation                     string
	Fork                          bool
	Argument, Result              int64
	Errno                         int
	Expected, Replacement, Actual uint32
}
type compressionLifecycleTrial struct {
	Filesystem, Scenario, Requested, Inline, Fault, Trace string
	FaultCount, FaultErrno, FaultSkip                     int
	Attribute, Fork, Data                                 []byte
	Observation                                           struct {
		FilesystemType                string `json:"filesystem_type"`
		ObserverHeldMetadataUnchanged *bool  `json:"observer_held_metadata_unchanged"`
		VolumeFlags                   uint32 `json:"volume_flags"`
		BeforeSize                    int64  `json:"before_size"`
		BeforeMode                    uint32 `json:"before_mode"`
		AfterMode                     uint32 `json:"after_mode"`
		TargetFlags                   uint32 `json:"target_flags"`
		TargetSize                    int64  `json:"target_size"`
	}
}

func compressionLifecycleTrials(t *testing.T) []compressionLifecycleTrial {
	return compressionTrials(t, "compression-lifecycle", 591)
}
func compressionTrials(t *testing.T, name string, count int) []compressionLifecycleTrial {
	t.Helper()
	f, e := os.Open("../../testdata/appledouble/native/" + name + ".json.gz")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	z, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var corpus struct {
		Schema int
		Cases  []compressionLifecycleTrial
	}
	if e = json.NewDecoder(z).Decode(&corpus); e != nil {
		t.Fatal(e)
	}
	if corpus.Schema != 1 || len(corpus.Cases) != count {
		t.Fatal("incomplete lifecycle fixture")
	}
	return corpus.Cases
}

type recordedCompressionCommit struct {
	t                        *testing.T
	events                   []compressionLifecycleEvent
	at                       int
	wantAttribute, attribute []byte
	mode, flags              uint32
	size                     int64
	failures                 int
}

func (b *recordedCompressionCommit) call(operation string, argument int64) (compressionLifecycleEvent, error) {
	b.t.Helper()
	if b.at >= len(b.events) {
		b.t.Fatalf("extra operation %s", operation)
	}
	e := b.events[b.at]
	b.at++
	if e.Operation != operation || e.Argument != argument {
		b.t.Fatalf("native operation %+v, Go %s(%d)", e, operation, argument)
	}
	if e.Errno == 0 {
		return e, nil
	}
	b.failures++
	err := fmt.Errorf("native errno %d", e.Errno)
	if operation == "attribute" && e.Errno == 13 {
		err = errors.Join(ErrCompressionAttributeAccess, err)
	}
	if operation == "ffsctl" && e.Errno == 35 {
		err = errors.Join(ErrStatFlagsAgain, err)
	}
	return e, err
}
func (b *recordedCompressionCommit) SetCompressionAttribute(value []byte) error {
	if !bytes.Equal(value, b.wantAttribute) {
		b.t.Fatal("attribute differs from independent native storage")
	}
	_, err := b.call("attribute", int64(len(value)))
	if err == nil {
		b.attribute = bytes.Clone(value)
	}
	return err
}
func (b *recordedCompressionCommit) Chmod(mode uint16) error {
	_, err := b.call("fchmod", int64(mode))
	if err == nil {
		b.mode = b.mode&0170000 | uint32(mode)&07777
	}
	return err
}
func (b *recordedCompressionCommit) TruncateData(size int64) error {
	_, err := b.call("ftruncate", size)
	if err == nil {
		b.size = size
	}
	return err
}
func (b *recordedCompressionCommit) ReadFlags() (uint32, error) {
	if b.at+1 >= len(b.events) || b.events[b.at].Operation != "ffsctl" || b.events[b.at+1].Operation != "cas-flags" {
		b.t.Fatal("read outside native comparison")
	}
	return b.events[b.at+1].Expected, nil
}
func (b *recordedCompressionCommit) CompareAndSwapFlags(expected, replacement uint32) (uint32, error) {
	_, err := b.call("ffsctl", 0xc00c4114)
	e, _ := b.call("cas-flags", 0)
	if e.Expected != expected || e.Replacement != replacement {
		b.t.Fatal("native flag comparison differs", e, expected, replacement)
	}
	if err == nil {
		b.flags = e.Actual
		if expected == e.Actual {
			b.flags = replacement
			b.size = int64(binary.LittleEndian.Uint64(b.attribute[8:]))
		}
	}
	return e.Actual, err
}
func (b *recordedCompressionCommit) SyncData() error { _, e := b.call("fsync", 0); return e }
func (b *recordedCompressionCommit) SetCompressionTimes(modify, access time.Time) error {
	if modify != time.Unix(1600000000, 0) || access != time.Unix(1550000000, 0) {
		b.t.Fatal("incorrect native times", modify, access)
	}
	_, e := b.call("futimes", modify.Unix())
	return e
}

func TestCommitCompressionNativeLifecycle(t *testing.T) {
	trials := compressionLifecycleTrials(t)
	compared := 0
	for index, trial := range trials {
		var events []compressionLifecycleEvent
		started := false
		for _, line := range strings.Split(strings.TrimSpace(trial.Trace), "\n") {
			if line == "" {
				continue
			}
			var event compressionLifecycleEvent
			if e := json.Unmarshal([]byte(line), &event); e != nil {
				t.Fatal(e)
			}
			if event.Operation == "attribute" {
				started = true
			}
			if started && !event.Fork && event.Operation != "close" {
				events = append(events, event)
			}
		}
		if !started {
			continue
		} // Native eligibility/storage stopped before this stage.
		compared++
		t.Run(fmt.Sprintf("%d/%s/%s/%s/%s/%s/%d/%d", index, trial.Filesystem, trial.Scenario, trial.Requested, trial.Inline, trial.Fault, trial.FaultCount, trial.FaultErrno), func(t *testing.T) {
			controlScenario := "ordinary"
			if trial.Scenario == "multi-block" {
				controlScenario = "multi-block"
			}
			var storage decmpfs.EncodedFile
			for _, candidate := range trials {
				if candidate.Filesystem == trial.Filesystem && candidate.Scenario == controlScenario && candidate.Requested == trial.Requested && candidate.Inline == trial.Inline && candidate.Fault == "" {
					storage = decmpfs.EncodedFile{Attribute: candidate.Attribute, ForkSize: int64(len(candidate.Fork))}
					break
				}
			}
			if storage.Attribute == nil {
				t.Fatal("missing independent native storage")
			}
			mode := trial.Observation.BeforeMode
			if trial.Scenario == "symlink" {
				mode = 0100600
			}
			b := &recordedCompressionCommit{t: t, events: events, wantAttribute: storage.Attribute, mode: mode, size: trial.Observation.BeforeSize}
			if trial.Scenario == "symlink" {
				b.size = 65536
			}
			if trial.Scenario == "hidden" {
				b.flags = 0x8000
			}
			source := StatCopySource{Mode: mode, Times: FileTimes{Modify: time.Unix(1600000000, 0), Access: time.Unix(1550000000, 0)}}
			result, err := CommitCompression(t.Context(), storage, source, b)
			wantActivated := trial.Observation.TargetFlags&UFCompressed != 0
			if result.Activated != wantActivated || result.Completed != strings.Contains(trial.Trace, `"operation":"futimes"`) || (err == nil) != wantActivated {
				t.Fatal(result, err, trial.Observation)
			}
			if b.at != len(events) || b.failures != len(result.Failures) {
				t.Fatal("incomplete native sequence/failure inventory", b.at, len(events), b.failures, result)
			}
			if b.flags != trial.Observation.TargetFlags || b.size != trial.Observation.TargetSize || !bytes.Equal(b.attribute, trial.Attribute) {
				t.Fatal("partial native state differs", b.flags, b.size, len(b.attribute), trial.Observation, len(trial.Attribute))
			}
			if trial.Scenario != "symlink" && b.mode != trial.Observation.AfterMode {
				t.Fatal("native permission outcome differs", b.mode, trial.Observation.AfterMode)
			}
		})
	}
	if compared != 362 {
		t.Fatal("incomplete native installation inventory", compared)
	}
}

type compressionCommitFunctions struct {
	compressionFlagFunctions
	attribute func([]byte) error
	mode      func(uint16) error
	truncate  func(int64) error
	sync      func() error
	times     func(time.Time, time.Time) error
}

func (b compressionCommitFunctions) SetCompressionAttribute(p []byte) error   { return b.attribute(p) }
func (b compressionCommitFunctions) Chmod(m uint16) error                     { return b.mode(m) }
func (b compressionCommitFunctions) TruncateData(n int64) error               { return b.truncate(n) }
func (b compressionCommitFunctions) SyncData() error                          { return b.sync() }
func (b compressionCommitFunctions) SetCompressionTimes(m, a time.Time) error { return b.times(m, a) }

func TestCommitCompressionCancellationAndValidation(t *testing.T) {
	storage := decmpfs.EncodedFile{Attribute: compressionMetadataHeader(8)[:16], ForkSize: 12}
	for _, point := range []string{"before", "attribute", "temporary-mode", "attribute-retry", "truncate", "flags", "sync", "times", "restore-mode"} {
		t.Run(point, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if point == "before" {
				cancel()
			}
			var events []string
			record := func(name string) {
				events = append(events, name)
				if name == point {
					cancel()
				}
			}
			attrs, modes := 0, 0
			b := compressionCommitFunctions{
				compressionFlagFunctions: compressionFlagFunctions{read: func() (uint32, error) { return 0, nil }, compare: func(a, b uint32) (uint32, error) { record("flags"); return a, nil }},
				attribute: func([]byte) error {
					attrs++
					if attrs == 1 {
						record("attribute")
						return ErrCompressionAttributeAccess
					}
					record("attribute-retry")
					return nil
				},
				mode: func(uint16) error {
					modes++
					if modes == 1 {
						record("temporary-mode")
					} else {
						record("restore-mode")
					}
					return nil
				},
				truncate: func(int64) error { record("truncate"); return nil },
				sync:     func() error { record("sync"); return nil },
				times: func(m, a time.Time) error {
					if m.Nanosecond() != 123456000 || a.Nanosecond() != 456789000 {
						t.Fatal("microsecond precision lost", m, a)
					}
					record("times")
					return nil
				},
			}
			source := StatCopySource{Mode: 0100755, Times: FileTimes{Modify: time.Unix(12, 123456789), Access: time.Unix(13, 456789123)}}
			result, err := CommitCompression(ctx, storage, source, b)
			if !errors.Is(err, context.Canceled) {
				t.Fatal(result, err)
			}
			if result.DataTruncated && (!result.Completed || !result.Activated || !result.TimesRestored || !result.ModeRestored) {
				t.Fatal("late cancellation stranded committed data", result, events)
			}
			if !result.DataTruncated && len(events) > 0 && events[len(events)-1] != point {
				t.Fatal("continued after early cancellation", events)
			}
		})
	}
	if _, e := CommitCompression(t.Context(), storage, StatCopySource{}, nil); !errors.Is(e, os.ErrInvalid) {
		t.Fatal(e)
	}
	b := compressionCommitFunctions{}
	for _, bad := range []decmpfs.EncodedFile{{}, {Attribute: storage.Attribute, ForkSize: -1}} {
		if _, e := CommitCompression(t.Context(), bad, StatCopySource{}, b); e == nil {
			t.Fatal("accepted invalid storage")
		}
	}
	if _, e := CommitCompression(t.Context(), storage, StatCopySource{Mode: 65536}, b); !errors.Is(e, os.ErrInvalid) {
		t.Fatal(e)
	}
}
