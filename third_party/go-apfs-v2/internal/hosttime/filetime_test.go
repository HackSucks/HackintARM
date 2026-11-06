package hosttime

import (
	"errors"
	"os"
	"testing"
	"time"
)

func TestCarrierWindowsTimeTicks(t *testing.T) {
	for _, tc := range []struct {
		name string
		when time.Time
		want uint64
	}{
		{"epoch", time.Unix(0, 0), 116444736000000000},
		{"first", time.Unix(-11644473600, 100), 1},
		{"fraction", time.Unix(946684800, 123456700), 125911584001234567},
		{"maximum", time.Unix(922337203685-11644473600, 477580700), 1<<63 - 1},
		{"precision", time.Unix(0, 1), 0},
		{"before-epoch", time.Unix(-11644473601, 0), 0},
		{"zero-sentinel", time.Unix(-11644473600, 0), 0},
		{"seconds-overflow", time.Unix(922337203686-11644473600, 0), 0},
		{"fraction-overflow", time.Unix(922337203685-11644473600, 477580800), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := WindowsTicks(tc.when)
			if got != tc.want || (tc.want == 0 && !errors.Is(err, os.ErrInvalid)) || (tc.want != 0 && err != nil) {
				t.Fatalf("ticks = %d, %v; want %d", got, err, tc.want)
			}
		})
	}
}
