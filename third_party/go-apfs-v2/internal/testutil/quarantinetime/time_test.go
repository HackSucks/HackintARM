package quarantinetime

import (
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	prefix, suffix := []byte("0086;"), []byte(";object-probe;")
	interval := Interval{time.Unix(0x6abd671a, 900000000).UTC(), time.Unix(0x6abd671b, 200000000).UTC()}
	for _, value := range []string{"0086;6abd671a;object-probe;", "0086;6abd671b;object-probe;"} {
		if err := Validate([]byte(value), prefix, suffix, interval); err != nil {
			t.Fatal(err)
		}
	}
	// A timestamp from the same second is valid even if its encoded instant is
	// before Start's fractional part; no whole-second margin is added.
	same := Interval{interval.Start, interval.Start.Add(time.Millisecond)}
	if err := Validate([]byte("0086;6abd671a;object-probe;"), prefix, suffix, same); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"0086;6abd6719;object-probe;", "0086;6abd671c;object-probe;", "0086;6553f100;object-probe;", "0080;6abd671a;object-probe;", "0086;6abd671a;other;", "0086;6abd671a;object-probe;id", "0086;6abd671A;object-probe;", "0086;zzzzzzzz;object-probe;", "0086;6abd671;object-probe;"} {
		if err := Validate([]byte(value), prefix, suffix, interval); err == nil {
			t.Fatal("invalid observation accepted", value)
		}
	}
	for _, bad := range []Interval{{}, {Start: interval.Start}, {End: interval.End}, {interval.End, interval.Start}, {time.Unix(-1, 0), time.Unix(1, 0)}, {interval.Start, time.Unix(int64(^uint32(0))+1, 0)}} {
		if err := Validate([]byte("0086;6abd671a;object-probe;"), prefix, suffix, bad); err == nil {
			t.Fatal("invalid interval accepted", bad)
		}
	}
	// Matching values do not excuse a stale timestamp: each invocation must pass.
	value := []byte("0086;6abd671a;object-probe;")
	later := Interval{interval.End, interval.End.Add(time.Second)}
	if err := Validate(value, prefix, suffix, later); err == nil {
		t.Fatal("equal stale value passed a later invocation")
	}
}
