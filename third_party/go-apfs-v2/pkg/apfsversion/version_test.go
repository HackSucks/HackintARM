package apfsversion

import (
	"errors"
	"testing"
)

func TestParseAndString(t *testing.T) {
	for _, s := range []string{"2332.140.13.702.2", "2811.160.7.0.4", "3288.1.3", "7", "0.1"} {
		v, err := Parse(s)
		if err != nil || v.String() != s {
			t.Fatalf("%q: %v %v", s, v, err)
		}
	}
	for _, bad := range []string{"", ".", "1.", ".1", "1..2", "01.2", "a.b", "-1", "1.2.x", "1234567890"} {
		if _, err := Parse(bad); !errors.Is(err, ErrInvalidVersion) {
			t.Fatalf("%q accepted: %v", bad, err)
		}
	}
	if MustParse("3288.1.3").Series() != 3288 || Version(nil).Series() != 0 || Version(nil).String() != "" || !Version(nil).IsZero() {
		t.Fatal("series or zero handling")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("MustParse accepted garbage")
		}
	}()
	MustParse("x")
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2332.140.13.702.2", "2811.160.7.0.4", -1},
		{"3288.1.3", "2811.160.7.0.4", 1},
		{"2811", "2811.0.0", 0},
		{"2811.1", "2811", 1},
		{"2811.160.7.0.4", "2811.160.7.0.4", 0},
	}
	for _, c := range cases {
		if got := MustParse(c.a).Compare(MustParse(c.b)); got != c.want {
			t.Fatalf("%s vs %s: %d", c.a, c.b, got)
		}
	}
}

func TestPackedRoundTrip(t *testing.T) {
	// Values read from real container superblocks.
	observed := map[uint64]string{
		2332140013702002: "2332.140.13.702.2",
		2811160007000004: "2811.160.7.0.4",
		3288001003000000: "3288.1.3.0.0",
	}
	for packed, want := range observed {
		v := DecodePacked(packed)
		if v.String() != want {
			t.Fatalf("%d decoded to %s", packed, v)
		}
		back, err := EncodePacked(v)
		if err != nil || back != packed {
			t.Fatalf("%s encoded to %d %v", v, back, err)
		}
	}
	if !DecodePacked(0).IsZero() {
		t.Fatal("zero packed version must decode to empty")
	}
	if p, err := EncodePacked(MustParse("3288.1.3")); err != nil || p != 3288001003000000 {
		t.Fatal(p, err)
	}
	if p, err := EncodePacked(nil); err != nil || p != 0 {
		t.Fatal(p, err)
	}
	for _, bad := range []Version{{1, 2, 3, 4, 5, 6}, {1, 1000}, {1, 2, -1}, {18446744}, {18700000}} {
		if _, err := EncodePacked(bad); !errors.Is(err, ErrPackedRange) {
			t.Fatalf("%v packed: %v", bad, err)
		}
	}
	if p, err := EncodePacked(Version{18446743, 999, 999, 999, 999}); err != nil || DecodePacked(p).Compare(Version{18446743, 999, 999, 999, 999}) != 0 {
		t.Fatal("largest packable version", p, err)
	}
	if _, err := EncodePacked(Version{5000}); err != nil {
		t.Fatal("first component is not limited to three digits", err)
	}
}

func TestParseStamp(t *testing.T) {
	for raw, want := range map[string]Stamp{
		"newfs_apfs (2811.160.7.0.4)":           {"newfs_apfs", MustParse("2811.160.7.0.4"), "2811.160.7.0.4"},
		"apfs_kext (2332.140.13.702.2)\x00\x00": {"apfs_kext", MustParse("2332.140.13.702.2"), "2332.140.13.702.2"},
		"go-apfs (apfswrite)":                   {"go-apfs", nil, "apfswrite"},
		"fsck_apfs (3288.1.3)":                  {"fsck_apfs", MustParse("3288.1.3"), "3288.1.3"},
	} {
		got, err := ParseStamp(raw)
		if err != nil || got.Tool != want.Tool || got.Detail != want.Detail || got.Version.Compare(want.Version) != 0 || (len(got.Version) == 0) != (len(want.Version) == 0) {
			t.Fatalf("%q: %+v %v", raw, got, err)
		}
		if got.IsApple() != !want.Version.IsZero() {
			t.Fatalf("%q apple=%v", raw, got.IsApple())
		}
	}
	if ParseStampMust("newfs_apfs (3288.1.3)").String() != "newfs_apfs (3288.1.3)" {
		t.Fatal("string form")
	}
	for _, bad := range []string{"", "newfs_apfs", "newfs_apfs ()", "(2811)", "newfs_apfs(2811)", "a (b) c", "new(fs) (1)"} {
		if _, err := ParseStamp(bad); !errors.Is(err, ErrInvalidStamp) {
			t.Fatalf("%q accepted: %v", bad, err)
		}
	}
	if (Stamp{}).String() != "" {
		t.Fatal("empty stamp string")
	}
}

func ParseStampMust(s string) Stamp {
	st, err := ParseStamp(s)
	if err != nil {
		panic(err)
	}
	return st
}

func TestLedger(t *testing.T) {
	if len(Releases()) != len(ledger) {
		t.Fatal("ledger copy")
	}
	for series, want := range map[int]int{2313: 15, 2317: 15, 2332: 15, 2632: 26, 2811: 26, 3288: 27} {
		major, exact, ok := MacOSMajor(series)
		if !ok || !exact || major != want {
			t.Fatalf("series %d: %d exact=%v ok=%v", series, major, exact, ok)
		}
		if r, ok := ReleaseForSeries(series); !ok || r.Series != series || r.MacOS == "" || r.Source == "" {
			t.Fatalf("series %d row %+v", series, r)
		}
	}
	for series, want := range map[int]int{2400: 15, 2700: 26, 3100: 26, 4000: 27} {
		major, exact, ok := MacOSMajor(series)
		if !ok || exact || major != want {
			t.Fatalf("inferred series %d: %d exact=%v ok=%v", series, major, exact, ok)
		}
	}
	if _, _, ok := MacOSMajor(1412); ok {
		t.Fatal("pre-ledger series attributed")
	}
	if _, ok := ReleaseForSeries(1); ok {
		t.Fatal("unknown series found")
	}
}

func TestAssessNativeMount(t *testing.T) {
	host15 := MustParse("2332.140.13.702.2")
	host26 := MustParse("2811.160.7.0.4")
	host27 := MustParse("3288.1.3")
	newer := Image{FormattedBy: ParseStampMust("newfs_apfs (3288.1.3)"), LastModifiedBy: ParseStampMust("apfs_kext (3288.1.3)"), NewestMounted: MustParse("3288.1.3")}
	if newer.NewestWriter().String() != "3288.1.3" {
		t.Fatal(newer.NewestWriter())
	}
	withNames := newer
	withNames.NamesInspected, withNames.UnrepresentableNames = true, 28
	clean := newer
	clean.NamesInspected = true
	own := Image{FormattedBy: ParseStampMust("newfs_apfs (2332.140.13.702.2)"), LastModifiedBy: ParseStampMust("apfs_kext (2332.140.13.702.2)"), NewestMounted: host15}
	goWritten := Image{FormattedBy: ParseStampMust("go-apfs (apfswrite)")}
	cases := []struct {
		name  string
		host  Version
		image Image
		want  Verdict
		code  string
	}{
		{"15 host, names present", host15, withNames, KnownDeadlock, CodeUnicodeNames},
		{"15 host, newer writer, names clean", host15, clean, Supported, CodeSupported},
		{"15 host, newer writer, not inspected", host15, newer, Unknown, CodeNewerWriter},
		{"15 host, own image, not inspected", host15, own, Supported, CodeSupported},
		{"15 host, go-apfs image, not inspected", host15, goWritten, Supported, CodeSupported},
		{"26 host, names present", host26, withNames, Supported, CodeSupported},
		{"26 host, 27 image not inspected", host26, newer, Supported, CodeSupported},
		{"27 host, names present", host27, withNames, Supported, CodeSupported},
		{"unknown host", MustParse("1412.1"), withNames, Unknown, CodeUnknownSeries},
		{"empty host", nil, own, Unknown, CodeUnknownSeries},
	}
	for _, c := range cases {
		got := AssessNativeMount(c.host, c.image)
		if got.Verdict != c.want || got.Code != c.code || got.Reason == "" {
			t.Fatalf("%s: %+v", c.name, got)
		}
		err := got.Error()
		if (err == nil) != (c.want == Supported) {
			t.Fatalf("%s: error %v", c.name, err)
		}
		var me *MountError
		if err != nil && (!errors.As(err, &me) || me.Assessment != got || err.Error() == "") {
			t.Fatalf("%s: error shape %v", c.name, err)
		}
	}
	for v, s := range map[Verdict]string{Unknown: "unknown", Supported: "supported", KnownDeadlock: "known-deadlock", Verdict(9): "unknown"} {
		if v.String() != s {
			t.Fatal(v, s)
		}
	}
}

func FuzzParseStamp(f *testing.F) {
	for _, seed := range []string{"newfs_apfs (2811.160.7.0.4)", "apfs_kext (3288.1.3)", "go-apfs (apfswrite)", "", "x (", "a (1.2.3) b"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		st, err := ParseStamp(s)
		if err != nil {
			if !errors.Is(err, ErrInvalidStamp) {
				t.Fatal(err)
			}
			return
		}
		if st.Tool == "" || st.Detail == "" {
			t.Fatalf("accepted %q as %+v", s, st)
		}
		if st.IsApple() {
			if _, err := EncodePacked(st.Version); err == nil {
				if DecodePacked(mustPack(st.Version)).Compare(st.Version) != 0 {
					t.Fatalf("packed round trip changed %s", st.Version)
				}
			}
		}
	})
}

func mustPack(v Version) uint64 {
	p, err := EncodePacked(v)
	if err != nil {
		panic(err)
	}
	return p
}
