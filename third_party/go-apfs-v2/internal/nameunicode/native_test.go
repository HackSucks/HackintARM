package nameunicode_test

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/deploymenttheory/go-apfs-v2/internal/nameunicode"
	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"
)

func TestNameCollationNativeEvidence(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, major := range []int{15, 26, 27} {
		t.Run(fmt.Sprint(major), func(t *testing.T) {
			p := filepath.Join(root, fmt.Sprintf("testdata/appledouble/native/name-collation-macos%d.json.gz", major))
			f, e := os.Open(p)
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			z, e := gzip.NewReader(f)
			if e != nil {
				t.Fatal(e)
			}
			defer z.Close()
			var c struct {
				Schema  int
				Sources map[string]string
				Cases   []struct{ ID, Created, Queried string }
				Volumes []struct {
					Kind   string
					Native struct {
						Sensitive bool `json:"case_sensitive"`
						Cases     []struct {
							ID, Created, Queried, Stored string
							CreateErrno                  int    `json:"create_errno"`
							LookupErrno                  int    `json:"lookup_errno"`
							Same                         bool   `json:"same_inode"`
							Inode                        uint64 `json:"created_inode"`
							Parent                       uint64 `json:"parent_inode"`
						}
					}
					Records []struct {
						ID, Name, Key, Value string
						Hash                 uint32
						Inode                uint64
					}
				}
			}
			if e = json.NewDecoder(z).Decode(&c); e != nil {
				t.Fatal(e)
			}
			if c.Schema != 1 || len(c.Cases) != 3753 || len(c.Volumes) != 4 {
				t.Fatal("incomplete native corpus")
			}
			reference, err := captureprovenance.Reference(os.DirFS(root), c.Sources)
			if err != nil {
				t.Fatal(err)
			}
			if err = captureprovenance.Verify(reference, c.Sources); err != nil {
				t.Fatal(err)
			}
			for p := range c.Sources {
				if len(p) > 8 && (p[:8] == "testdata" || p[:8] == "scripts/" || p[:8] == ".github/") {
					if _, err := captureprovenance.ReadSource(reference, c.Sources, p); err != nil {
						t.Fatal(err)
					}
				}
			}
			decode := func(s string) []byte {
				b, e := hex.DecodeString(s)
				if e != nil {
					t.Fatal(e)
				}
				return b
			}
			for vi, v := range c.Volumes {
				if v.Kind != []string{"APFS", "APFSX", "HFS+", "HFSX"}[vi] || len(v.Native.Cases) != 3753 {
					t.Fatal("incorrect volume corpus")
				}
				records := map[string]struct {
					Name, Key, Value string
					Hash             uint32
					Inode            uint64
				}{}
				for _, r := range v.Records {
					if _, exists := records[r.ID]; exists {
						t.Fatal("duplicate record")
					}
					records[r.ID] = struct {
						Name, Key, Value string
						Hash             uint32
						Inode            uint64
					}{r.Name, r.Key, r.Value, r.Hash, r.Inode}
				}
				for i, n := range v.Native.Cases {
					input := c.Cases[i]
					if n.ID != input.ID || n.Created != input.Created || n.Queried != input.Queried {
						t.Fatal("native input inventory differs")
					}
					if n.CreateErrno != 0 {
						if _, ok := records[n.ID]; ok {
							t.Fatal("record for rejected name")
						}
						continue
					}
					a, b := decode(n.Created), decode(n.Queried)
					r, ok := records[n.ID]
					if !ok || r.Name != n.Stored || r.Inode != n.Inode {
						t.Fatalf("missing native record:%s", n.ID)
					}
					t.Run(v.Kind+"/"+n.ID, func(t *testing.T) {
						if vi < 2 {
							d := apfs.NewDirectoryEntryRecord()
							if e := d.ReadKeyData(decode(r.Key)); e != nil {
								t.Fatal(e)
							}
							if e := d.ReadValueData(decode(r.Value)); e != nil {
								t.Fatal(e)
							}
							if d.Identifier != n.Inode || d.NameHash != r.Hash {
								t.Fatal("raw record identity/hash mismatch")
							}
							if got := apfs.CalculateNameHash(a, !v.Native.Sensitive); got != r.Hash {
								t.Fatalf("hash=%x native=%x", got, r.Hash)
							}
							if got := apfs.CalculateNameHashFromUTF16(utf16.Encode([]rune(string(a))), !v.Native.Sensitive); got != r.Hash {
								t.Fatalf("UTF16hash=%x native=%x", got, r.Hash)
							}
							equal := apfs.CompareNamesWithUTF8(a, b, !v.Native.Sensitive) == 0
							if equal != n.Same {
								t.Fatalf("comparison=%v native=%v", equal, n.Same)
							}
							if (apfs.CompareNamesWithUTF16(utf16.Encode([]rune(string(a))), utf16.Encode([]rune(string(b))), !v.Native.Sensitive) == 0) != n.Same {
								t.Fatal("UTF16comparison differs")
							}
						} else {
							if got := []byte(nameunicode.HFS(string(a))); !bytes.Equal(got, decode(n.Stored)) {
								t.Fatalf("stored=%x native=%s", got, n.Stored)
							}
							if equal := hfsplus.CompareNames(string(a), string(b), v.Native.Sensitive) == 0; equal != n.Same {
								t.Fatalf("comparison=%v native=%v", equal, n.Same)
							}
						}
					})
				}
			}
		})
	}
}
