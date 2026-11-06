package xattrintent

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestXattrIntentNativeSource(t *testing.T) {
	f, err := os.Open("../../../testdata/appledouble/native/xattr-intent.json.gz")
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
		SourceSHA256 map[string]string
		Cases        []struct {
			Name                []byte
			Intent              uint32
			Sandboxed, Preserve bool
		}
	}
	if err := json.NewDecoder(z).Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 4384 {
		t.Fatal("incomplete controlled source corpus", len(fixture.Cases))
	}
	const source = "testdata/appledouble/native/xattr-intent.c"
	b, err := os.ReadFile("../../../" + source)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if fixture.SourceSHA256[source] != hex.EncodeToString(sum[:]) {
		t.Fatal("changed intent oracle")
	}
	const url = "https://raw.githubusercontent.com/apple-oss-distributions/copyfile/9f91eb6ced021952278816cdc76ad68da8631ccb/"
	for name, want := range map[string]string{"xattr_flags.c": "991a340ad26bf9086f9fcbca8eafb0dee4c2ab38e41d152c60fa218e5d4226dc", "xattr_flags.h": "0fd2d35d0ae3efba30d30b8c470dae4bc42972455c6d8d5246fec44732f43d49", "xattr_properties.h": "5be7721f4dc452af3864d15240c4afccde87cc160842c92c092d745b2ba6fe7e"} {
		if fixture.SourceSHA256[url+name] != want {
			t.Fatal("changed Apple source pin", name)
		}
	}
	sandboxCases := map[bool]int{}
	for i, c := range fixture.Cases {
		sandboxCases[c.Sandboxed]++
		if got := PreserveXattrForIntent(string(c.Name), c.Intent, c.Sandboxed); got != c.Preserve {
			t.Fatalf("native intent case%d: got%t want%t", i, got, c.Preserve)
		}
	}
	if sandboxCases[true] != 2192 || sandboxCases[false] != 2192 {
		t.Fatal("sandbox corpus incomplete")
	}
}
