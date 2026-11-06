package hostdata_test

import (
	"errors"
	"io/fs"
	"reflect"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

type statBackend struct {
	events   []string
	times    [][2]time.Time
	modes    []uint16
	flags    uint32
	queries  []hostdata.SecurityCopyVolume
	queryErr error
	positive bool
}

func (b *statBackend) SetTimes(m, a time.Time) error {
	b.events = append(b.events, "times")
	b.times = append(b.times, [2]time.Time{m, a})
	return nil
}
func (b *statBackend) Chown(_, _ uint32) error { b.events = append(b.events, "owner"); return nil }
func (b *statBackend) Chmod(m uint16) error {
	b.events = append(b.events, "mode")
	b.modes = append(b.modes, m)
	return nil
}
func (b *statBackend) ReadFlags() (uint32, error) {
	b.events = append(b.events, "read-flags")
	return b.flags, nil
}
func (b *statBackend) CompareAndSwapFlags(expected, replacement uint32) (uint32, error) {
	b.events = append(b.events, "cas")
	old := b.flags
	if old == expected {
		b.flags = replacement
	}
	return old, nil
}
func (b *statBackend) Chflags(f uint32) error {
	b.events = append(b.events, "flags")
	b.flags = f
	return nil
}
func (b *statBackend) NoSetID(v hostdata.SecurityCopyVolume) (bool, error) {
	b.queries = append(b.queries, v)
	return b.positive, b.queryErr
}

func TestStatCopyValidation(t *testing.T) {
	s := hostdata.StatCopySource{Mode: 0106751}
	if r, e := hostdata.CopyStat(s, hostdata.StatCopyOptions{}, nil); !errors.Is(e, fs.ErrInvalid) || r.Completed || r.Writes != 0 {
		t.Fatalf("nil backend: %+v %v", r, e)
	}
	for _, source := range []bool{true, false} {
		b := &statBackend{}
		o := hostdata.StatCopyOptions{VolumePolicy: b, SourceNoSetID: source, DestinationNoSetID: !source}
		r, e := hostdata.CopyStat(s, o, b)
		if !errors.Is(e, fs.ErrInvalid) || r.Completed || len(b.events) != 0 || len(b.queries) != 0 {
			t.Fatalf("mixed policy: %+v %v", r, e)
		}
	}
}
func TestStatCopyCapturedPolicy(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    hostdata.StatCopyOptions
		mode uint16
	}{
		{"ordinary", hostdata.StatCopyOptions{}, 06751},
		{"source", hostdata.StatCopyOptions{SourceNoSetID: true}, 0751},
		{"destination", hostdata.StatCopyOptions{DestinationNoSetID: true}, 0751},
		{"always", hostdata.StatCopyOptions{AlwaysCopySetID: true, ForbidCopySetID: true, SourceNoSetID: true}, 06751},
		{"forbid", hostdata.StatCopyOptions{ForbidCopySetID: true}, 0751},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &statBackend{}
			r, e := hostdata.CopyStat(hostdata.StatCopySource{Mode: 0106751}, tc.o, b)
			if e != nil || !r.Completed || !r.FlagsApplied || r.Writes != 4 || !reflect.DeepEqual(b.modes, []uint16{tc.mode}) || len(r.VolumeQueries) != 0 {
				t.Fatalf("%+v %v mode %v", r, e, b.modes)
			}
		})
	}
}
func TestStatCopyTimeAndModeContract(t *testing.T) {
	// Unix zero, negative nanoseconds and independent time zones survive request
	// preparation. Birth/change deliberately cannot become timestamp requests.
	times := hostdata.FileTimes{Birth: time.Unix(900, 1), Change: time.Unix(800, 2), Modify: time.Unix(0, 0).In(time.FixedZone("source", 3600)), Access: time.Unix(-1, 999999999)}
	for _, mode := range []uint32{0, 0100000, 0047755, 0126751, 0xffffffff} {
		b := &statBackend{}
		s := hostdata.StatCopySource{Times: times, Mode: mode, Flags: 0x20}
		before := s
		r, e := hostdata.CopyStat(s, hostdata.StatCopyOptions{AlwaysCopySetID: true}, b)
		if e != nil || !r.Completed || s != before || len(b.times) != 2 || b.times[0] != [2]time.Time{times.Modify, times.Access} || b.times[1] != b.times[0] || b.modes[0] != uint16(mode&^0170000) {
			t.Fatalf("request mutation/narrowing: %+v %+v %v", s, b, e)
		}
		if !reflect.DeepEqual(b.events, []string{"times", "owner", "mode", "read-flags", "cas", "times"}) {
			t.Fatal(b.events)
		}
	}
}
func TestStatCopyUnknownPolicy(t *testing.T) {
	sentinel := errors.New("volume unavailable")
	b := &statBackend{positive: true, queryErr: sentinel}
	r, e := hostdata.CopyStat(hostdata.StatCopySource{Mode: 0106751}, hostdata.StatCopyOptions{VolumePolicy: b}, b)
	if e != nil || b.modes[0] != 06751 || len(r.VolumeQueries) != 2 {
		t.Fatalf("unknown treated positive: %+v %v", r, e)
	}
	for _, q := range r.VolumeQueries {
		if q.NoSetID || !errors.Is(q.Err, sentinel) {
			t.Fatal(q)
		}
	}
}
