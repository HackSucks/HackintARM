package appledouble

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
)

func TestFilesystemRemovalPackedEmpty(t *testing.T) {
	f, err := os.Open("../../testdata/appledouble/native/metadata-filesystem-packed-empty-macos27.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var corpus struct {
		Complete bool
		Profile  string
		Seed     []byte
	}
	if err := json.NewDecoder(z).Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	if !corpus.Complete || corpus.Profile != "packed-empty" {
		t.Fatal("incomplete native packed evidence")
	}
	snapshot, err := DecodeStream(t.Context(), bytes.NewReader(corpus.Seed), DefaultStreamLimits())
	if err != nil {
		t.Fatal("COPYFILE_PACK remains a valid snapshot", err)
	}
	found := false
	for _, attr := range snapshot.Attrs {
		if attr.Name == "com.example.phase2" {
			found = true
			if attr.Value.Size() != 0 {
				t.Fatal("lost native empty value")
			}
		}
	}
	if !found {
		t.Fatal("missing native empty value")
	}
	if _, err := DecodeFilesystemStream(t.Context(), bytes.NewReader(corpus.Seed), DefaultStreamLimits()); !errors.Is(err, ErrNotAppleDouble) {
		t.Fatal("native rejects the entire packed namespace", err)
	}
	file, err := os.CreateTemp(t.TempDir(), "carrier")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Write(corpus.Seed); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"com.example.phase2", FinderInfoName, ResourceForkName, "com.example.absent"} {
		result, err := RemoveFilesystemAttribute(t.Context(), removalTestFile{file, int64(len(corpus.Seed))}, name)
		if !errors.Is(err, ErrNotAppleDouble) || result.Removed || result.Empty {
			t.Fatal(name, result, err)
		}
	}
	after, err := io.ReadAll(io.NewSectionReader(file, 0, int64(len(corpus.Seed))))
	if err != nil || !bytes.Equal(after, corpus.Seed) {
		t.Fatal("rejected namespace changed bytes", err)
	}
}
