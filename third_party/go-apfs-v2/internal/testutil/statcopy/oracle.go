// Package statcopy supplies native-oracle replay for stat restoration tests.
package statcopy

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

type Source struct {
	UID, GID, Mode, Flags uint32
	Times                 [4]int64
}
type Metadata struct {
	UID, GID, Mode, Flags uint32
	Times                 [6]int64
	ACL, Xattr            string
}
type Event struct {
	Operation                               string
	Code, Errno                             int
	UID, GID, Mode, Flags, Expected, Actual uint32
	Times                                   [4]int64
	NoSetID                                 bool
}
type Observation struct {
	Source                                   Source
	Events                                   []Event
	Code, Errno                              int
	SourceBefore, SourceAfter, Before, After Metadata
	IdentityUnchanged, PayloadUnchanged      bool
	Filesystem                               string
}
type Case struct {
	Name, Kind                                      string
	SourceFlags, TargetFlags                        uint32
	Options, SourcePolicy, TargetPolicy, Fault, CAS int
	Native                                          Observation
}
type Fixture struct {
	Revision, Host, HelperSHA256, CopyfileSHA256, PrivateSHA256, FSCTLSHA256 string
	Models, Applications                                                     []Case
}
type NativeError int

func (e NativeError) Error() string { return fmt.Sprintf("native errno %d", e) }
func nativeError(e Event) error {
	if e.Code == 0 {
		return nil
	}
	err := error(NativeError(e.Errno))
	if e.Operation == "compare-flags" && e.Errno == 35 {
		err = errors.Join(hostdata.ErrStatFlagsAgain, err)
	}
	return err
}
func Options(o int) hostdata.StatCopyOptions {
	return hostdata.StatCopyOptions{AlwaysCopySetID: o&1 != 0, ForbidCopySetID: o&2 != 0, MakeInvisible: o&4 != 0, PreserveDestinationTracked: o&8 != 0}
}
func (s Source) Go() hostdata.StatCopySource {
	return hostdata.StatCopySource{UID: s.UID, GID: s.GID, Mode: s.Mode, Flags: s.Flags, Times: hostdata.FileTimes{Modify: time.Unix(s.Times[0], s.Times[1]), Access: time.Unix(s.Times[2], s.Times[3])}}
}

type backend struct {
	want, got []Event
	mismatch  error
}

func (b *backend) record(e Event) (Event, error) {
	i := len(b.got)
	if i >= len(b.want) {
		b.mismatch = fmt.Errorf("unexpected event %+v", e)
		return e, b.mismatch
	}
	w := b.want[i]
	e.Code, e.Errno = w.Code, w.Errno
	switch e.Operation {
	case "read-flags", "compare-flags":
		e.Actual = w.Actual
	case "volume-source", "volume-destination":
		e.NoSetID = w.NoSetID
	}
	b.got = append(b.got, e)
	if !reflect.DeepEqual(e, w) {
		b.mismatch = fmt.Errorf("event %d got %+v want %+v", i, e, w)
		return e, b.mismatch
	}
	return e, nativeError(e)
}
func (b *backend) SetTimes(m, a time.Time) error {
	_, err := b.record(Event{Operation: "times", Times: [4]int64{m.Unix(), int64(m.Nanosecond()), a.Unix(), int64(a.Nanosecond())}})
	return err
}
func (b *backend) Chown(u, g uint32) error {
	_, err := b.record(Event{Operation: "ownership", UID: u, GID: g})
	return err
}
func (b *backend) Chmod(m uint16) error {
	_, err := b.record(Event{Operation: "mode", Mode: uint32(m)})
	return err
}
func (b *backend) ReadFlags() (uint32, error) {
	e, err := b.record(Event{Operation: "read-flags"})
	return e.Actual, err
}
func (b *backend) CompareAndSwapFlags(x, n uint32) (uint32, error) {
	e, err := b.record(Event{Operation: "compare-flags", Expected: x, Flags: n})
	return e.Actual, err
}
func (b *backend) Chflags(f uint32) error {
	_, err := b.record(Event{Operation: "flags", Flags: f})
	return err
}
func (b *backend) NoSetID(v hostdata.SecurityCopyVolume) (bool, error) {
	e, err := b.record(Event{Operation: "volume-" + string(v)})
	return e.NoSetID, err
}
func Replay(tc Case) (hostdata.StatCopyResult, []Event, error) {
	b := &backend{want: tc.Native.Events}
	options := Options(tc.Options)
	options.VolumePolicy = b
	result, err := hostdata.CopyStat(tc.Native.Source.Go(), options, b)
	if err != nil || b.mismatch != nil {
		return result, b.got, fmt.Errorf("execute: %v; requests: %v", err, b.mismatch)
	}
	if !result.Completed || tc.Native.Code != 0 || !reflect.DeepEqual(b.got, tc.Native.Events) {
		return result, b.got, fmt.Errorf("completion/order mismatch")
	}
	writes, comparisons := 0, 0
	fallback, applied := false, false
	var failures []hostdata.StatCopyFailure
	var queries []hostdata.SecurityCopyVolumeQuery
	for _, e := range tc.Native.Events {
		err := nativeError(e)
		if strings.HasPrefix(e.Operation, "volume-") {
			q := hostdata.SecurityCopyVolumeQuery{Volume: hostdata.SecurityCopyVolume(strings.TrimPrefix(e.Operation, "volume-")), NoSetID: e.NoSetID, Err: err}
			if err != nil {
				q.NoSetID = false
			}
			queries = append(queries, q)
			continue
		}
		if e.Operation != "read-flags" {
			writes++
		}
		if err != nil {
			failures = append(failures, hostdata.StatCopyFailure{Operation: e.Operation, Err: err})
		}
		if e.Operation == "compare-flags" {
			comparisons++
			if err == nil && e.Expected == e.Actual {
				applied = true
			}
		}
		if e.Operation == "flags" {
			fallback = true
			applied = err == nil
		}
	}
	if result.Writes != writes || result.FlagComparisons != comparisons || result.FlagsFallback != fallback || result.FlagsApplied != applied || !reflect.DeepEqual(result.VolumeQueries, queries) || !reflect.DeepEqual(result.Failures, failures) {
		return result, b.got, fmt.Errorf("diagnostics mismatch: %+v", result)
	}
	return result, b.got, nil
}
func Protocol(events []Event) string {
	var b strings.Builder
	for _, e := range events {
		switch e.Operation {
		case "volume-source", "volume-destination", "read-flags":
			fmt.Fprintln(&b, e.Operation)
		case "times":
			fmt.Fprintf(&b, "times %d %d %d %d\n", e.Times[0], e.Times[1], e.Times[2], e.Times[3])
		case "ownership":
			fmt.Fprintf(&b, "ownership %d %d\n", e.UID, e.GID)
		case "mode":
			fmt.Fprintf(&b, "mode %d\n", e.Mode)
		case "compare-flags":
			fmt.Fprintf(&b, "compare-flags %d %d\n", e.Expected, e.Flags)
		case "flags":
			fmt.Fprintf(&b, "flags %d\n", e.Flags)
		default:
			panic("unknown event")
		}
	}
	return b.String()
}
