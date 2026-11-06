package hfsplus

import (
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
)

type nameAdmissionWriter struct{ calls int }

func (w *nameAdmissionWriter) WriteAt([]byte, int64) (int, error) {
	w.calls++
	return 0, io.ErrClosedPipe
}

func TestCreationNamePreflight(t *testing.T) {
	cycle := &Entry{Name: "cycle", Mode: os.ModeDir}
	cycle.Children = []*Entry{cycle}
	for _, tc := range []struct {
		name        string
		children    []*Entry
		insensitive bool
		want        error
	}{
		{"dot", []*Entry{{Name: "."}}, false, syscall.EEXIST},
		{"dotdot", []*Entry{{Name: ".."}}, false, syscall.EEXIST},
		{"ignored dot", []*Entry{{Name: ".\u200d"}}, true, nil},
		{"ignored dotdot", []*Entry{{Name: "..\u200d"}}, true, nil},
		{"ignored only", []*Entry{{Name: "\u200d"}}, true, nil},
		{"nil", []*Entry{nil}, false, syscall.EINVAL},
		{"cycle", []*Entry{cycle}, false, syscall.EINVAL},
		{"empty", []*Entry{{Name: ""}}, false, syscall.ENOENT},
		{"slash", []*Entry{{Name: "a/b"}}, false, syscall.EINVAL},
		{"nul", []*Entry{{Name: "a\x00b"}}, false, syscall.EINVAL},
		{"long", []*Entry{{Name: strings.Repeat("é", 128)}}, false, syscall.ENAMETOOLONG},
		{"escaped long", []*Entry{{Name: strings.Repeat("a", 254) + "\x80"}}, false, syscall.ENAMETOOLONG},
		{"canonical", []*Entry{{Name: "é"}, {Name: "e\u0301"}}, false, syscall.EEXIST},
		{"escaped alias", []*Entry{{Name: "x\x80y"}, {Name: "x%80y"}}, false, syscall.EEXIST},
		{"case", []*Entry{{Name: "A"}, {Name: "a"}}, true, syscall.EEXIST},
		{"sensitive", []*Entry{{Name: "A"}, {Name: "a"}}, false, nil},
		{"no full fold", []*Entry{{Name: "ß"}, {Name: "ss"}}, true, nil},
		{"nested", []*Entry{{Name: "dir", Mode: os.ModeDir, Children: []*Entry{{Name: "A"}, {Name: "a"}}}}, true, syscall.EEXIST},
		{"unwritten", []*Entry{{Name: "file", Children: []*Entry{{Name: ""}}}}, false, nil},
		{"length boundary", []*Entry{{Name: strings.Repeat("a", 255)}, {Name: strings.Repeat("é", 127)}, {Name: "x\x80y"}}, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := &Entry{Children: tc.children}
			w := &nameAdmissionWriter{}
			err := CreateImage(w, 0, "Names", root, &CreateOptions{CaseInsensitive: tc.insensitive})
			if tc.want != nil {
				if !errors.Is(err, tc.want) || w.calls != 0 {
					t.Fatalf("err=%v want=%v writes=%d", err, tc.want, w.calls)
				}
			} else if !errors.Is(err, io.ErrClosedPipe) || w.calls == 0 {
				t.Fatalf("admitted name err=%v writes=%d", err, w.calls)
			}
		})
	}
	if err := validateCreationNames(nil, false); !errors.Is(err, syscall.EINVAL) {
		t.Fatal(err)
	}
}

// Every output stage must surface destination failure and stop immediately;
// valid names must not make a partially written image appear successful.
type nameFaultWriter struct{ calls, failAt int }

func (w *nameFaultWriter) WriteAt(p []byte, _ int64) (int, error) {
	w.calls++
	if w.calls == w.failAt {
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}
func TestCreationOutputFailureBoundaries(t *testing.T) {
	root := &Entry{Children: []*Entry{{Name: "é", Data: []byte("content"), Xattrs: map[string][]byte{"user.test": []byte("attribute")}}}}
	complete := &nameFaultWriter{}
	if err := CreateImage(complete, 0, "Names", root, nil); err != nil {
		t.Fatal(err)
	}
	if complete.calls < 8 {
		t.Fatal("incomplete writer stages", complete.calls)
	}
	for n := 1; n <= complete.calls; n++ {
		out := &nameFaultWriter{failAt: n}
		if err := CreateImage(out, 0, "Names", root, nil); !errors.Is(err, io.ErrClosedPipe) || out.calls != n {
			t.Fatalf("stage=%d calls=%d error=%v", n, out.calls, err)
		}
	}
}
