package hostdata

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestRootReplacementWindowsSparse(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(map[bool]string{false: "discard", true: "commit"}[commit], func(t *testing.T) {
			dir := t.TempDir()
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			path := filepath.Join(dir, "source")
			source, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			if err := replacementSparse(source); err != nil {
				t.Fatal(err)
			}
			const length = int64(4<<30) + 17
			if err := source.Truncate(length); err != nil {
				t.Fatal(err)
			}
			for _, offset := range []int64{0, 1 << 30, length - 4} {
				if _, err := source.WriteAt([]byte("data"), offset); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path+":ordinary", []byte("metadata"), 0600); err != nil {
				t.Fatal(err)
			}
			named, err := os.OpenFile(path+":sparse", os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if err := replacementSparse(named); err != nil {
				t.Fatal(err)
			}
			if err := named.Truncate(131072); err != nil {
				t.Fatal(err)
			}
			if _, err := named.WriteAt([]byte("named"), 65536); err != nil {
				t.Fatal(err)
			}
			if err := named.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := source.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if err := root.Link("source", "neighbour"); err != nil {
				t.Fatal(err)
			}
			r, err := PrepareReplacementAt(source, root, ".")
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			// All sparse old main-data blocks must be excluded from preparation.
			st, err := r.File.Stat()
			if err != nil || st.Size() != 0 {
				t.Fatalf("old main data copied: %v %v", st, err)
			}
			if _, err := r.File.WriteAt([]byte("replacement"), 0); err != nil {
				t.Fatal(err)
			}
			if err := r.File.Truncate(11); err != nil {
				t.Fatal(err)
			}
			if err := r.RestoreMetadata(); err != nil {
				t.Fatal(err)
			}
			basic, err := replacementBasic(r.File)
			if err != nil || basic.Attributes&windows.FILE_ATTRIBUTE_SPARSE_FILE == 0 {
				t.Fatalf("sparse attribute lost: %#v %v", basic, err)
			}
			for _, stream := range []string{":ordinary", ":sparse"} {
				want, err := os.ReadFile(path + stream)
				if err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(filepath.Join(dir, r.Path) + stream)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("stream %s: %v", stream, err)
				}
			}
			if err := r.File.Close(); err != nil {
				t.Fatal(err)
			}
			if err := source.Close(); err != nil {
				t.Fatal(err)
			}
			if commit {
				if err := root.Rename(r.Path, "source"); err != nil {
					t.Fatal(err)
				}
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			after, err := root.Stat("source")
			if err != nil || os.SameFile(before, after) == commit {
				t.Fatalf("replacement identity: %v", err)
			}
			neighbour, err := root.Open("neighbour")
			if err != nil {
				t.Fatal(err)
			}
			defer neighbour.Close()
			for _, offset := range []int64{0, 1 << 30, length - 4} {
				p := make([]byte, 4)
				if _, err := neighbour.ReadAt(p, offset); err != nil || string(p) != "data" {
					t.Fatalf("source changed: %q %v", p, err)
				}
			}
			if commit {
				got, err := root.ReadFile("source")
				if err != nil || string(got) != "replacement" {
					t.Fatalf("replacement data: %q %v", got, err)
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 2 {
				t.Fatalf("staging leaked: %v %v", entries, err)
			}
		})
	}
}
