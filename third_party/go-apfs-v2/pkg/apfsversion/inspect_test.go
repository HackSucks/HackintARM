package apfsversion

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

// writeImage builds a small APFS image with go-apfs containing ASCII names,
// a Unicode 15 name and Unicode 16 names that macOS 15 refuses with EILSEQ.
func writeImage(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "names.img")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	root := &apfswrite.Entry{Name: "", Mode: os.ModeDir, Children: []*apfswrite.Entry{
		{Name: "collation", Mode: os.ModeDir, Children: []*apfswrite.Entry{
			{Name: "ascii", Mode: os.ModeDir, Children: []*apfswrite.Entry{{Name: "x"}, {Name: "y"}}},
			{Name: "canonical", Mode: os.ModeDir, Children: []*apfswrite.Entry{{Name: "café"}}},
			{Name: "fold-A7CE", Mode: os.ModeDir, Children: []*apfswrite.Entry{{Name: "꟎"}, {Name: "꟎x"}}},
			{Name: "fold-16EA0", Mode: os.ModeDir, Children: []*apfswrite.Entry{{Name: "\U00016EA0"}}},
		}},
	}}
	opts := &apfswrite.CreateOptions{TargetVersion: osversion.Version{Major: 27}, Volumes: []apfswrite.VolumeSpec{{Name: "Names", Root: root}}}
	if err := apfswrite.CreateContainer(f, 16<<20, opts); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInspectCountsUnrepresentableNames(t *testing.T) {
	path := writeImage(t)
	for major, want := range map[int]int{15: 3, 26: 0, 27: 0} {
		in, err := Inspect(path, major)
		if err != nil {
			t.Fatalf("macOS %d: %v", major, err)
		}
		if len(in.Volumes) != 1 || in.HostMajor != major || !in.NewestMounted.IsZero() {
			t.Fatalf("macOS %d: %+v", major, in)
		}
		v := in.Volumes[0]
		if v.Name != "Names" || v.FormattedBy.Tool != "go-apfs" || v.FormattedBy.IsApple() || v.Entries != 11 || v.UnrepresentableNames != want || len(v.Samples) != want {
			t.Fatalf("macOS %d: %+v", major, v)
		}
		image := in.Image(0)
		if !image.NamesInspected || image.UnrepresentableNames != want {
			t.Fatalf("macOS %d image %+v", major, image)
		}
		host := map[int]Version{15: MustParse("2332.140.13.702.2"), 26: MustParse("2811.160.7.0.4"), 27: MustParse("3288.1.3")}[major]
		a := AssessNativeMount(host, image)
		if (a.Verdict == KnownDeadlock) != (major == 15) {
			t.Fatalf("macOS %d assessment %+v", major, a)
		}
	}
	in, err := Inspect(path, 0)
	if err != nil || in.HostMajor != 0 || in.Volumes[0].Entries != 0 || in.Volumes[0].UnrepresentableNames != 0 || in.Image(0).NamesInspected {
		t.Fatalf("uninspected names: %+v %v", in, err)
	}
	if _, err := Inspect(path, 14); !errors.Is(err, ErrHostMajor) {
		t.Fatal(err)
	}
	if _, err := Inspect(filepath.Join(t.TempDir(), "missing"), 15); err == nil {
		t.Fatal("missing image accepted")
	}
	if _, err := ReadNewestMounted(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing image accepted")
	}
}

func TestRepresentable(t *testing.T) {
	cases := []struct {
		name  string
		major int
		want  bool
	}{
		{"ascii", 15, true},
		{"café", 15, true},
		{"꟎", 15, false},
		{"꟎", 26, true},
		{"꟎", 27, true},
		{"\U00016EA0", 15, false},
		{"\xff\xfe", 27, false},
	}
	for _, c := range cases {
		if got := representable([]byte(c.name), c.major); got != c.want {
			t.Fatalf("%+q on macOS %d: %v", c.name, c.major, got)
		}
	}
}

type shortReader struct{}

func (shortReader) ReadAt([]byte, int64) (int, error) { return 0, errors.New("short") }

func TestReadNewestMountedErrors(t *testing.T) {
	if _, err := readNewestMounted(shortReader{}, 0); err == nil {
		t.Fatal("short read accepted")
	}
}
