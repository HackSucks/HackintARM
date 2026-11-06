package osversion

import (
	"context"
	"errors"
	"testing"
)

func TestVersion(t *testing.T) {
	for _, c := range []struct {
		input string
		want  Version
	}{
		{"15", Version{15, 0, 0}}, {"26.6", Version{26, 6, 0}}, {"27.0.1", Version{27, 0, 1}},
		{"0015.07.01", Version{15, 7, 1}}, {"4294967295.4294967295.4294967295", Version{^uint32(0), ^uint32(0), ^uint32(0)}},
	} {
		t.Run(c.input, func(t *testing.T) {
			got, err := Parse(c.input)
			if err != nil || got != c.want {
				t.Fatal(got, err)
			}
			again, err := Parse(got.String())
			if err != nil || again != got {
				t.Fatal(again, err)
			}
		})
	}
	for _, value := range []string{"", "0", "0.1", ".15", "15.", "15..1", "15.1.2.3", "-15", "+15", "15.-1", "15.0.beta", " 15", "15\n", "１５", "15\x00", "4294967296", "15.4294967296", "15.0.4294967296"} {
		if got, err := Parse(value); !errors.Is(err, ErrVersion) || got != (Version{}) {
			t.Fatal(value, got, err)
		}
	}
	ordered := []Version{{15, 0, 0}, {15, 0, 1}, {15, 1, 0}, {26, 0, 0}, {27, 0, 0}}
	for i, a := range ordered {
		for j, b := range ordered {
			want := 0
			if i < j {
				want = -1
			}
			if i > j {
				want = 1
			}
			if got := a.Compare(b); got != want {
				t.Fatal(a, b, got, want)
			}
		}
	}
}

func TestProductCapture(t *testing.T) {
	for _, text := range []string{"ProductVersion: 15.7", "ProductName:\t\tmacOS\nProductVersion:\t\t15.7\nBuildVersion:\t24G\n", "\n ProductVersion: 15.7\r\n"} {
		got, err := ParseProductVersion(text)
		if err != nil || got != (Version{15, 7, 0}) {
			t.Fatal(got, err)
		}
	}
	for _, text := range []string{"", "BuildVersion: 15.7", "ProductVersion:", "ProductVersion: 15.7 extra", "ProductVersion: beta", "ProductVersion: 15\nProductVersion: 15"} {
		if got, err := ParseProductVersion(text); !errors.Is(err, ErrVersion) || got != (Version{}) {
			t.Fatal(text, got, err)
		}
	}
}

func TestExplicitMacOSProfiles(t *testing.T) {
	for _, c := range []struct {
		version Version
		want    MacOSProfile
	}{
		{Version{15, 0, 0}, MacOS15}, {Version{15, 7, 1}, MacOS15}, {Version{26, 6, 2}, MacOS26}, {Version{27, 0, 1}, MacOS27},
	} {
		got, err := ProfileForMacOS(c.version)
		if err != nil || got != c.want {
			t.Fatal(got, err)
		}
	}
	for _, version := range []Version{{}, {10, 15, 7}, {14, 8, 0}, {16, 0, 0}, {25, 0, 0}, {28, 0, 0}} {
		if got, err := ProfileForMacOS(version); !errors.Is(err, ErrMacOSProfile) || got != 0 {
			t.Fatal(got, err)
		}
	}
}

func TestDetectProvider(t *testing.T) {
	sentinel := errors.New("native read failure")
	if got, err := detect(t.Context(), func() (string, error) { return "27.0.1", nil }); err != nil || got != (Version{27, 0, 1}) {
		t.Fatal(got, err)
	}
	if _, err := detect(t.Context(), func() (string, error) { return "", sentinel }); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	if _, err := detect(t.Context(), func() (string, error) { return "not a product version", nil }); !errors.Is(err, ErrVersion) {
		t.Fatal(err)
	}
	before, cancelBefore := context.WithCancel(t.Context())
	cancelBefore()
	if _, err := detect(before, func() (string, error) { t.Fatal("read after cancellation"); return "", nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	during, cancelDuring := context.WithCancel(t.Context())
	defer cancelDuring()
	if _, err := detect(during, func() (string, error) { cancelDuring(); return "27", nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func FuzzVersion(f *testing.F) {
	for _, seed := range []string{"15.7.1", "26", "27.0.1", "", "4294967296", "+15", "15..1"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		v, err := Parse(input)
		if err != nil {
			return
		}
		round, err := Parse(v.String())
		if err != nil || round != v || v.Compare(round) != 0 {
			t.Fatal(v, round, err)
		}
	})
}
