package hfsplus

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// countingOpen wraps content as an Entry.Open that records how it was used.
type countingOpen struct {
	content []byte
	opens   int
	closes  int
}

func (c *countingOpen) open() (io.ReadCloser, error) {
	c.opens++
	return &countingReader{Reader: bytes.NewReader(c.content), owner: c}, nil
}

type countingReader struct {
	io.Reader
	owner *countingOpen
}

func (r *countingReader) Close() error {
	r.owner.closes++
	return nil
}

// lazily rewrites every regular file below e to supply its content through Open
// rather than Data, returning the sources so a test can inspect them.
func lazily(e *Entry) []*countingOpen {
	var sources []*countingOpen
	for _, child := range e.Children {
		if child.Mode.IsRegular() {
			source := &countingOpen{content: child.Data}
			child.Open, child.Size, child.Data = source.open, int64(len(child.Data)), nil
			sources = append(sources, source)
		}
		sources = append(sources, lazily(child)...)
	}
	return sources
}

// TestOpenMatchesData is the property the feature rests on: where the bytes
// come from must not reach the image. A tree supplying its content through Open
// produces the same volume, byte for byte, as one holding it in Data.
func TestOpenMatchesData(t *testing.T) {
	held, _ := sampleTree()
	streamed, _ := sampleTree()
	sources := lazily(streamed)

	want := buildImage(t, held, nil)
	got := buildImage(t, streamed, nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("an image built through Open differs from one built from Data (%d vs %d bytes)", len(got), len(want))
	}

	for _, source := range sources {
		// An empty file has no extent to fill, so there is nothing to open.
		wantOpens := 1
		if len(source.content) == 0 {
			wantOpens = 0
		}
		if source.opens != wantOpens || source.closes != wantOpens {
			t.Errorf("content of %d bytes was opened %d times and closed %d, want %d of each",
				len(source.content), source.opens, source.closes, wantOpens)
		}
	}
}

// TestOpenHardLinksReadContentOnce checks that names sharing a link group are
// still one copy of the content, read once, when that content is lazy.
func TestOpenHardLinksReadContentOnce(t *testing.T) {
	content := bytes.Repeat([]byte("shared "), 2000)
	first := &countingOpen{content: content}
	second := &countingOpen{content: content}
	root := &Entry{Children: []*Entry{
		{Name: "a", Mode: 0o644, Open: first.open, Size: int64(len(content)), LinkGroup: 7},
		{Name: "b", Mode: 0o644, Open: second.open, Size: int64(len(content)), LinkGroup: 7},
	}}

	v, err := New(bytes.NewReader(buildImage(t, root, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, name := range []string{"a", "b"} {
		f, err := v.Open(name)
		if err != nil {
			t.Fatalf("Open(%s): %v", name, err)
		}
		got, err := io.ReadAll(f)
		f.Close()
		if err != nil || !bytes.Equal(got, content) {
			t.Errorf("%s: read %d bytes (err %v), want the %d shared ones", name, len(got), err, len(content))
		}
	}
	if first.opens+second.opens != 1 {
		t.Errorf("linked content was opened %d times, want once", first.opens+second.opens)
	}
}

// TestOpenRejectsContentOfTheWrongLength covers the one thing a lazy source can
// get wrong after the layout is fixed.
func TestOpenRejectsContentOfTheWrongLength(t *testing.T) {
	content := bytes.Repeat([]byte("x"), 10000)
	cases := []struct {
		name string
		size int64
		want string
	}{
		{"shorter than Size", int64(len(content)) + 1, "short of"},
		{"longer than Size", int64(len(content)) - 1, "continues past"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			source := &countingOpen{content: content}
			root := &Entry{Children: []*Entry{
				{Name: "lazy", Mode: 0o644, Open: source.open, Size: tc.size},
			}}
			err := CreateImage(&memWriterAt{}, 0, "LEN", root, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CreateImage = %v, want an error mentioning %q", err, tc.want)
			}
			if source.closes != 1 {
				t.Errorf("the rejected content was closed %d times, want once", source.closes)
			}
		})
	}
}

// TestOpenErrorFailsTheWrite confirms a source that cannot be opened stops the
// image rather than leaving a file of zeros behind.
func TestOpenErrorFailsTheWrite(t *testing.T) {
	failure := errors.New("source went away")
	root := &Entry{Children: []*Entry{
		{Name: "lazy", Mode: 0o644, Size: 1, Open: func() (io.ReadCloser, error) { return nil, failure }},
	}}
	if err := CreateImage(&memWriterAt{}, 0, "ERR", root, nil); !errors.Is(err, failure) {
		t.Fatalf("CreateImage = %v, want the source's own error", err)
	}
}

// TestOpenValidation covers the entries validateTree refuses before anything
// is written.
func TestOpenValidation(t *testing.T) {
	open := (&countingOpen{content: []byte("content")}).open
	cases := []struct {
		name  string
		entry *Entry
		want  string
	}{
		{"both sources", &Entry{Name: "f", Mode: 0o644, Data: []byte("content"), Open: open, Size: 7}, "both Data and Open"},
		{"size without open", &Entry{Name: "f", Mode: 0o644, Size: 7}, "Size without Open"},
		{"negative size", &Entry{Name: "f", Mode: 0o644, Open: open, Size: -1}, "no data fork can have"},
		{"directory", &Entry{Name: "d", Mode: os.ModeDir | 0o755, Open: open, Size: 7}, "not a regular file"},
		{"symlink", &Entry{Name: "l", Mode: os.ModeSymlink | 0o755, Open: open, Size: 7}, "not a regular file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CreateImage(&memWriterAt{}, 0, "BAD", &Entry{Children: []*Entry{tc.entry}}, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CreateImage = %v, want an error mentioning %q", err, tc.want)
			}
		})
	}
}
