package hostdata

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

type replacementCompressionSample struct {
	Name                   string
	Type                   uint32
	Plain, Attribute, Fork []byte
}

func replacementCompressionSamples(t *testing.T) []replacementCompressionSample {
	t.Helper()
	f, err := os.Open("../../testdata/appledouble/native/decmpfs-formats.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var captured struct {
		Cases []replacementCompressionSample
	}
	if err := json.NewDecoder(z).Decode(&captured); err != nil {
		t.Fatal(err)
	}
	if len(captured.Cases) != 14 {
		t.Fatalf("native corpus changed: %d", len(captured.Cases))
	}
	return captured.Cases
}

// The same captured native storage cases exercise the exclusion policy on all
// hosts. No host-specific bit, syscall or substitute compression format is used.
func TestReplacementCompressedMetadata(t *testing.T) {
	for _, tc := range replacementCompressionSamples(t) {
		t.Run(tc.Name, func(t *testing.T) {
			fork, err := os.Create(filepath.Join(t.TempDir(), "fork"))
			if err != nil {
				t.Fatal(err)
			}
			defer fork.Close()
			if _, err := fork.Write(tc.Fork); err != nil {
				t.Fatal(err)
			}
			var copied []byte
			var forkOpened, birth bool
			attrs := map[string][]byte{}
			err = copyReplacementMetadataUsing(replacementCopyOps{
				compressed: true,
				list:       func() ([]string, error) { return []string{DecmpfsName, ResourceForkName, "user.test"}, nil },
				read: func(name string, limit int) ([]byte, bool, error) {
					value := []byte("metadata")
					if name == DecmpfsName {
						value = tc.Attribute
					}
					if len(value) > limit {
						t.Fatal("read exceeded bound")
					}
					return value, true, nil
				},
				write:    func(name string, value []byte) error { attrs[name] = bytes.Clone(value); return nil },
				openFork: func() (replacementFork, error) { forkOpened = true; return fork, nil },
				replaceFork: func(value appledouble.Value) error {
					copied = make([]byte, value.Size())
					if len(copied) == 0 {
						return nil
					}
					_, err := value.ReadAt(copied, 0)
					return err
				},
				birth: func() error { birth = true; return nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			if !birth || len(attrs) != 1 || string(attrs["user.test"]) != "metadata" {
				t.Fatal("lost independent metadata", attrs)
			}
			if tc.Type%2 == 0 {
				if forkOpened || len(copied) != 0 {
					t.Fatal("copied compression-owned fork")
				}
			} else if !forkOpened || !bytes.Equal(copied, tc.Fork) {
				t.Fatal("lost independent fork")
			}
		})
	}
}

func TestReplacementCompressedMetadataFailures(t *testing.T) {
	for _, tc := range []struct {
		name             string
		value            []byte
		present          bool
		fault, errorWant error
	}{
		{"read", nil, false, io.ErrUnexpectedEOF, io.ErrUnexpectedEOF},
		{"missing", nil, false, nil, ErrXattrChanged},
		{"truncated", []byte("fpmc"), true, nil, os.ErrInvalid},
		{"unknown", append([]byte("fpmc\xff\x00\x00\x00"), make([]byte, 8)...), true, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := copyReplacementMetadataUsing(replacementCopyOps{compressed: true,
				read: func(string, int) ([]byte, bool, error) { return tc.value, tc.present, tc.fault },
				list: func() ([]string, error) { t.Fatal("continued after invalid compression"); return nil, nil },
			})
			if err == nil || (tc.errorWant != nil && !errors.Is(err, tc.errorWant)) {
				t.Fatal(err)
			}
		})
	}
}
