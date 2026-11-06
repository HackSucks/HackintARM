package pathnative

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"
)

// All hosts validate the native fixture inventory, including source mode and
// process umask observations that cannot be inferred from the receiving host.
func TestPathNativeFixtureInventory(t *testing.T) {
	file, err := os.Open("../../../testdata/appledouble/native/path-copyfile.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	z, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	data, err := io.ReadAll(io.LimitReader(z, 16<<20))
	if err != nil || len(data) == 16<<20 {
		t.Fatalf("invalid or oversized native inventory: %v", err)
	}
	var fixture Fixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	helper, err := os.ReadFile("../../../testdata/appledouble/native/path-copyfile.c")
	if err != nil {
		t.Fatal(err)
	}
	if fixture.HelperSHA256 != fmt.Sprintf("%x", sha256.Sum256(helper)) || fixture.Revision == "" || fixture.Host == "" {
		t.Fatal("native source provenance changed or absent")
	}
	provider, err := os.ReadFile("../../../testdata/appledouble/native/xattr-provider-context.h")
	if err != nil || fixture.ProviderSHA256 != fmt.Sprintf("%x", sha256.Sum256(provider)) {
		t.Fatal("native provider context source provenance changed or absent", err)
	}
	generated := Cases()
	if len(fixture.Cases) != 552 || len(generated) != len(fixture.Cases) {
		t.Fatalf("incomplete inventory: native%d generated%d", len(fixture.Cases), len(generated))
	}
	for i, observed := range fixture.Cases {
		observed.Native = Observation{}
		if !reflect.DeepEqual(observed, generated[i]) {
			t.Fatalf("native input changed at case%d: %+v != %+v", i, observed, generated[i])
		}
	}
}

func TestPathNativeContextIdentity(t *testing.T) {
	p := PathProviderContext{State: RemovalContext{Device: 11, Inode: 22, UID: 501, GID: 20, Mode: 0600, MountFlags: 7, ACLHex: "retained"}}
	c := InputContext{SourceProviderFollow: p, SourceProviderNoFollow: p, DestinationProviderFollow: p, DestinationProviderNoFollow: p, TargetProvider: p}
	got := c.WithoutObjectIdentity()
	for _, state := range []PathProviderContext{got.SourceProviderFollow, got.SourceProviderNoFollow, got.DestinationProviderFollow, got.DestinationProviderNoFollow, got.TargetProvider} {
		want := p
		want.State.Device, want.State.Inode = 0, 0
		if state != want {
			t.Fatal("non-identity provider context was changed", state)
		}
	}
	if c.SourceProviderFollow != p || c.DestinationProviderFollow != p || c.TargetProvider != p {
		t.Fatal("original recorded identity was mutated")
	}
}
