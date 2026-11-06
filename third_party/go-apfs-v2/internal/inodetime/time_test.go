package inodetime

import (
	"errors"
	"io/fs"
	"math"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

func TestInodeTimesEncoding(t *testing.T) {
	for _, hfs := range []bool{false, true} {
		values := []time.Time{time.Unix(0, 0), time.Unix(12345, 987654321), time.Unix(2212122495, 999999999)}
		bad := []time.Time{time.Time{}, time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)}
		if hfs {
			values = append(values, time.Unix(-2082844800, 0))
			bad = append(bad, time.Unix(-2082844801, 999999999), time.Unix(2212122496, 0))
		} else {
			values = append(values, time.Unix(0, math.MinInt64), time.Unix(0, math.MaxInt64))
			bad = append(bad, time.Unix(0, math.MinInt64).Add(-1), time.Unix(0, math.MaxInt64).Add(1))
		}
		for _, value := range values {
			for _, clamp := range []bool{false, true} {
				for field := 0; field < 4; field++ {
					times := hostdata.FileTimes{Birth: time.Unix(1, 0), Modify: time.Unix(1, 0), Change: time.Unix(1, 0), Access: time.Unix(1, 0)}
					pointers := []*time.Time{&times.Birth, &times.Modify, &times.Change, &times.Access}
					*pointers[field] = value
					limit := time.Unix(100, 999999999)
					got, e := Encode(times, limit, clamp, hfs)
					if e != nil {
						t.Fatal(e)
					}
					for i, p := range pointers {
						want := *p
						if i == 1 && clamp && want.After(limit) {
							want = limit
						}
						bits := uint64(want.UnixNano())
						if hfs {
							bits = uint64(want.Unix() + 2082844800)
						}
						if got[i] != bits {
							t.Fatalf("field %d %v: %v", i, hfs, got)
						}
					}
				}
			}
		}
		for _, value := range bad {
			for field := 0; field < 4; field++ {
				times := hostdata.FileTimes{Birth: time.Unix(1, 0), Modify: time.Unix(1, 0), Change: time.Unix(1, 0), Access: time.Unix(1, 0)}
				p := []*time.Time{&times.Birth, &times.Modify, &times.Change, &times.Access}
				*p[field] = value
				got, e := Encode(times, time.Unix(100, 0), false, hfs)
				if !errors.Is(e, fs.ErrInvalid) || got != [4]uint64{} {
					t.Fatalf("invalid %v field%d: %v %v", value, field, got, e)
				}
			}
		}
	}
}
