package hostdata

import (
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

func TestHeldMetadataNativeFixture(t *testing.T) {
	f, err := os.Open("../../testdata/appledouble/native/held-metadata.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var fixture struct {
		Cases        int `json:"cases"`
		Observations map[string]struct {
			UID        uint32             `json:"uid"`
			GID        uint32             `json:"gid"`
			Mode       uint32             `json:"mode"`
			Flags      uint32             `json:"flags"`
			Times      []int64            `json:"times"`
			Properties map[string]*string `json:"properties"`
		} `json:"observations"`
	}
	if err = json.NewDecoder(z).Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Cases != 16 || len(fixture.Observations) != 16 {
		t.Fatal("incomplete native fixture")
	}
	for name, v := range fixture.Observations {
		t.Run(name, func(t *testing.T) {
			if len(v.Times) != 8 || len(v.Properties) != 6 {
				t.Fatal("incomplete native observation")
			}
			p := aclmeta.DarwinChmodProperties{}
			for key, ptr := range v.Properties {
				if ptr == nil {
					continue
				}
				b, e := hex.DecodeString(*ptr)
				if e != nil {
					t.Fatal(e)
				}
				switch key {
				case "1", "2":
					if len(b) != 4 {
						t.Fatal(key)
					}
					n := binary.LittleEndian.Uint32(b)
					if key == "1" {
						p.UID = &n
					} else {
						p.GID = &n
					}
				case "4":
					if len(b) != 2 {
						t.Fatal(key)
					}
					n := uint32(binary.LittleEndian.Uint16(b))
					p.Mode = &n
				case "3", "6":
					if len(b) != 16 {
						t.Fatal(key)
					}
					uuid := [16]byte(b)
					if key == "3" {
						p.OwnerUUID = &uuid
					} else {
						p.GroupUUID = &uuid
					}
				case "100":
					p.RawSecurity, e = appledouble.ParseDarwinFileSecurity(b)
					if e != nil {
						t.Fatal(e)
					}
				default:
					t.Fatal(key)
				}
			}
			state := MetadataState{Security: SecurityCopySource{UID: v.UID, GID: v.GID, Mode: v.Mode, Properties: p}, Stat: StatCopySource{UID: v.UID, GID: v.GID, Mode: v.Mode, Flags: v.Flags, Times: FileTimes{
				Birth: time.Unix(v.Times[0], v.Times[1]), Modify: time.Unix(v.Times[2], v.Times[3]), Change: time.Unix(v.Times[4], v.Times[5]), Access: time.Unix(v.Times[6], v.Times[7]),
			}}}
			logical, e := NewLogicalMetadata(state)
			if e != nil {
				t.Fatal(e)
			}
			if got := logical.Snapshot(); !reflect.DeepEqual(got, state) {
				t.Fatalf("native metadata changed: %+v", got)
			}
			acl, e := logical.CaptureACL()
			if e != nil {
				t.Fatal(e)
			}
			if name[len(name)-3:] == "acl" && (acl.Security.ACL == nil || len(acl.Security.ACL.Entries) != 1) {
				t.Fatal("nonempty native ACL lost")
			}
		})
	}
}
