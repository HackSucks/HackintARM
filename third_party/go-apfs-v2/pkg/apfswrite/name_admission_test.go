package apfswrite

import (
	"errors"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
	"io"
	"syscall"
	"testing"
)

type admissionWriter struct{ calls int }

func (w *admissionWriter) WriteAt([]byte, int64) (int, error) { w.calls++; return 0, io.ErrClosedPipe }

func TestCreationNamePolicy(t *testing.T) {
	cycle := &Entry{Name: "cycle"}
	cycle.Children = []*Entry{cycle}
	for _, c := range []struct {
		name   string
		target osversion.Version
		volume VolumeSpec
		want   error
	}{
		{name: "empty default", volume: VolumeSpec{}},
		{name: "explicit supported", target: osversion.Version{Major: 26}, volume: VolumeSpec{RootFiles: []RootFile{{Name: "x\uA7CEy"}}}},
		{name: "target fifteen", target: osversion.Version{Major: 15}, volume: VolumeSpec{RootFiles: []RootFile{{Name: "x\uA7CEy"}}}, want: syscall.EILSEQ},
		{name: "nil entry", volume: VolumeSpec{Root: &Entry{Children: []*Entry{nil}}}, want: syscall.EINVAL},
		{name: "cycle", volume: VolumeSpec{Root: &Entry{Children: []*Entry{cycle}}}, want: syscall.EINVAL},
		{name: "empty name", volume: VolumeSpec{RootFiles: []RootFile{{Name: ""}}}, want: syscall.EINVAL},
		{name: "case collision", volume: VolumeSpec{RootFiles: []RootFile{{Name: "A"}, {Name: "a"}}}, want: syscall.EEXIST},
		{name: "full fold collision", volume: VolumeSpec{RootFiles: []RootFile{{Name: "Straße"}, {Name: "STRASSE"}}}, want: syscall.EEXIST},
		{name: "canonical collision", volume: VolumeSpec{CaseSensitive: true, RootFiles: []RootFile{{Name: "é"}, {Name: "e\u0301"}}}, want: syscall.EEXIST},
		{name: "sensitive different", volume: VolumeSpec{CaseSensitive: true, RootFiles: []RootFile{{Name: "A"}, {Name: "a"}}}},
		{name: "nested invalid", volume: VolumeSpec{Root: &Entry{Children: []*Entry{{Name: "d", Children: []*Entry{{Name: "\x80"}}}}}}, want: syscall.EILSEQ},
		{name: "separate directories", volume: VolumeSpec{Root: &Entry{Children: []*Entry{{Name: "a", Children: []*Entry{{Name: "same"}}}, {Name: "b", Children: []*Entry{{Name: "same"}}}}}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if e := validateCreationNames(c.target, []VolumeSpec{c.volume}); !errors.Is(e, c.want) {
				t.Fatalf("got %v want %v", e, c.want)
			}
		})
	}
	if validateCreationNames(osversion.Version{Major: 14}, nil) == nil {
		t.Fatal("unsupported target")
	}
}

func TestCreationNamesBeforeOutput(t *testing.T) {
	for _, opts := range []*CreateOptions{
		{TargetVersion: osversion.Version{Major: 14}},
		{RootFiles: []RootFile{{Name: "."}}},
		{RootFiles: []RootFile{{Name: ".."}}},
		{TargetVersion: osversion.Version{Major: 15}, RootFiles: []RootFile{{Name: "x\uA7CEy"}}},
		{RootFiles: []RootFile{{Name: "Σ"}, {Name: "ς"}}},
		{Volumes: []VolumeSpec{{Name: "one", RootFiles: []RootFile{{Name: "okay"}}}, {Name: "two", RootFiles: []RootFile{{Name: "a"}, {Name: "A"}}}}},
	} {
		w := &admissionWriter{}
		if e := CreateContainer(w, 0, opts); e == nil {
			t.Fatal("invalid creation succeeded")
		}
		if w.calls != 0 {
			t.Fatal("invalid names modified destination")
		}
	}
	for _, target := range []osversion.Version{{}, {Major: 26}, {Major: 27}} {
		w := &admissionWriter{}
		e := CreateContainer(w, 0, &CreateOptions{TargetVersion: target, RootFiles: []RootFile{{Name: "x\uA7CEy"}}})
		if !errors.Is(e, io.ErrClosedPipe) || w.calls == 0 {
			t.Fatal("admitted target did not reach output", target, e, w.calls)
		}
	}
}

func TestCreationAdmissionIgnoresUnwrittenFileChildren(t *testing.T) {
	entry := &Entry{Name: "regular", Mode: 0600, Children: []*Entry{nil, {Name: "\x80"}}}
	if err := validateCreationNames(osversion.Version{}, []VolumeSpec{{Root: &Entry{Children: []*Entry{entry}}}}); err != nil {
		t.Fatal(err)
	}
}
