package hostdata

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestQuarantineCapturePortable(t *testing.T) {
	c := QuarantineProcessCapture{Profile: appledouble.QuarantineMacOS27, Flags: 0x200, Agent: []byte{'A', '\\', 0xff}, Metadata: []byte{0xff, 0}, Tracking: []byte{1, 2}}
	encoded, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var decoded QuarantineProcessCapture
	if err := json.Unmarshal(encoded, &decoded); err != nil || !reflect.DeepEqual(c, decoded) {
		t.Fatalf("raw snapshot JSON: %v", err)
	}
	p, err := decoded.Process()
	if err != nil || p.Flags != c.Flags || p.Agent != string(c.Agent) || p.Absent {
		t.Fatalf("planner input: %#v %v", p, err)
	}
	for _, bad := range []QuarantineProcessCapture{
		{Profile: 99}, {Agent: make([]byte, 256)}, {Metadata: make([]byte, 65)}, {Tracking: make([]byte, 65)},
		{Absent: true, Flags: 1}, {Absent: true, Agent: []byte{1}}, {Absent: true, Metadata: []byte{1}}, {Absent: true, Tracking: []byte{1}},
	} {
		if _, err := bad.Process(); !errors.Is(err, appledouble.ErrQuarantineContext) {
			t.Fatalf("invalid snapshot %#v: %v", bad, err)
		}
	}
	absent := QuarantineProcessCapture{Profile: appledouble.QuarantineMacOS26, Absent: true}
	if p, err := absent.Process(); err != nil || !p.Absent {
		t.Fatalf("absence: %#v %v", p, err)
	}
	if _, err := CaptureQuarantineProcess(nil); !errors.Is(err, os.ErrInvalid) { //nolint:staticcheck // Exercise the documented invalid-context rejection.
		t.Fatalf("nil context: %v", err)
	} //nolint:staticcheck // Exercise the public invalid-input contract.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := CaptureQuarantineProcess(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
}

func TestQuarantineCaptureObservations(t *testing.T) {
	ctx := context.Background()
	source := &QuarantineProcessCapture{Profile: appledouble.QuarantineMacOS27, Flags: 0x200, Agent: []byte("raw\\agent")}
	query := func() (*QuarantineProcessCapture, error) { return source, nil }
	got, err := captureQuarantineProcess(ctx, query, func() error { t.Fatal("present capture confirmed absence"); return nil })
	if err != nil || !reflect.DeepEqual(got, source) {
		t.Fatalf("capture: %#v %v", got, err)
	}
	source.Agent[0] = 'x'
	if string(got.Agent) != "raw\\agent" {
		t.Fatal("snapshot borrowed provider storage")
	}
	denied := errors.New("permission denied")
	for _, tc := range []struct {
		name                                  string
		first, second                         *QuarantineProcessCapture
		firstErr, secondErr, confirmErr, want error
		cancelAt                              int
	}{
		{name: "first-error", firstErr: denied, want: denied},
		{name: "missing-first", want: appledouble.ErrQuarantineContext},
		{name: "invalid-first", first: &QuarantineProcessCapture{Profile: 99}, want: appledouble.ErrQuarantineContext},
		{name: "confirm-error", first: &QuarantineProcessCapture{Absent: true}, confirmErr: denied, want: denied},
		{name: "second-error", first: source, secondErr: denied, want: denied},
		{name: "missing-second", first: source, want: ErrQuarantineCaptureChanged},
		{name: "changed", first: source, second: &QuarantineProcessCapture{Flags: 1}, want: ErrQuarantineCaptureChanged},
		{name: "cancel-first", first: source, cancelAt: 1, want: context.Canceled},
		{name: "cancel-second", first: source, second: source, cancelAt: 2, want: context.Canceled},
		{name: "confirmed-absent", first: &QuarantineProcessCapture{Absent: true}, second: &QuarantineProcessCapture{Absent: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			n := 0
			_, err := captureQuarantineProcess(ctx, func() (*QuarantineProcessCapture, error) {
				n++
				if n == tc.cancelAt {
					cancel()
				}
				if n == 1 {
					return tc.first, tc.firstErr
				}
				return tc.second, tc.secondErr
			}, func() error { return tc.confirmErr })
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
}
