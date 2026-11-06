package hostdata

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

type filesystemMetadataCorpus struct {
	Name, Path, Profile string
	Cases               int
}

func (c filesystemMetadataCorpus) target() string {
	if c.Profile == "attribute-target" {
		return "._input"
	}
	return "input"
}

func filesystemMetadataCorpora() []filesystemMetadataCorpus {
	fresh := os.Getenv("APFS_METADATA_FILESYSTEM_PRODUCERS")
	var result []filesystemMetadataCorpus
	for _, major := range []int{15, 26, 27} {
		for _, profile := range []string{"", "packed-empty", "attribute-target"} {
			// The retained packed corpus was executed on 27. Fresh CI requires all
			// three actual producers; never label a 27 observation as an older host.
			if profile != "" && major != 27 && fresh == "" {
				continue
			}
			name, cases := fmt.Sprint(major), 960
			path := fmt.Sprintf("../../testdata/appledouble/native/metadata-filesystem-macos%d.json.gz", major)
			if profile != "" {
				name, cases = fmt.Sprintf("%s-%d", profile, major), 96
				if profile == "attribute-target" {
					cases = 192
				}
				path = fmt.Sprintf("../../testdata/appledouble/native/metadata-filesystem-%s-macos%d.json.gz", profile, major)
			}
			if fresh != "" {
				path = filepath.Join(fresh, fmt.Sprintf("filesystem-metadata-macos%d", major), "native.json")
				if profile == "packed-empty" {
					path = filepath.Join(filepath.Dir(path), "packed", "native.json")
				} else if profile == "attribute-target" {
					path = filepath.Join(filepath.Dir(path), "attribute-target", "native.json")
				}
			}
			result = append(result, filesystemMetadataCorpus{name, path, profile, cases})
		}
	}
	return result
}

func TestFilesystemMetadataCorpusInventory(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		t.Run(fmt.Sprint(fresh), func(t *testing.T) {
			directory := ""
			expected := 5
			if fresh {
				directory = t.TempDir()
				expected = 9
			}
			t.Setenv("APFS_METADATA_FILESYSTEM_PRODUCERS", directory)
			corpus := filesystemMetadataCorpora()
			if len(corpus) != expected {
				t.Fatal("lost native input profile", len(corpus), expected)
			}
			seen := map[string]bool{}
			for _, entry := range corpus {
				if seen[entry.Name] || entry.Path == "" {
					t.Fatal("duplicate or missing source", entry)
				}
				seen[entry.Name] = true
				if fresh {
					relative, err := filepath.Rel(directory, entry.Path)
					if err != nil || !filepath.IsLocal(relative) {
						t.Fatal("producer path escaped evidence root", entry, err)
					}
				}
			}
		})
	}
}
