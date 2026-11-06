package acl

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestACLIdentityCapturePublicSnapshot(t *testing.T) {
	f, err := os.Open("../../../testdata/appledouble/native/acl-identity-capture.json.gz")
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
		Snapshot     appledouble.ACLIdentitySnapshot
		Forward      []struct {
			Query appledouble.ACLIdentity
			UUID  [16]byte
		}
		Reverse []struct {
			UUID      [16]byte
			Principal appledouble.ACLPrincipal
			Found     bool
		}
	}
	if err := json.NewDecoder(z).Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"testdata/appledouble/native/acl-identity.c", "testdata/appledouble/native/acl-identity-capture.c"} {
		b, err := os.ReadFile("../../../" + p)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(b)
		if hex.EncodeToString(h[:]) != fixture.SourceSHA256[p] {
			t.Fatalf("changed native observer: %s", p)
		}
	}
	if len(fixture.Forward) != 12 || len(fixture.Reverse) < 9 {
		t.Fatal("incomplete public account fixture")
	}
	resolve, lookup, err := fixture.Snapshot.Resolvers()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fixture.Forward {
		if f.Query.ID != nil && *f.Query.ID != 0 && *f.Query.ID != ^uint32(0) {
			t.Fatal("unexpected non-public fixture account ID")
		}
		if f.Query.ID == nil {
			switch f.Query.Name {
			case "root", "wheel", "daemon", "nobody", "appledouble-no-such-account-01234567":
			default:
				t.Fatal("unexpected fixture account name")
			}
		}
		u, err := resolve(f.Query)
		if err != nil || u != f.UUID {
			t.Fatal("source forward replay mismatch", err)
		}
	}
	for _, r := range fixture.Reverse {
		p, found, err := lookup(r.UUID)
		if err != nil || p != r.Principal || found != r.Found {
			t.Fatal("source reverse replay mismatch", err)
		}
	}
}

func TestACLIdentityCaptureArguments(t *testing.T) {
	//nolint:staticcheck // Verify rejection of an invalid nil context at the public boundary.
	if _, err := NewNativeACLIdentityCapture(nil); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	for _, n := range []int{0, -1} {
		if _, err := NewNativeACLIdentityCaptureWithLimit(context.Background(), n); !errors.Is(err, os.ErrInvalid) {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewNativeACLIdentityCapture(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	c, err := NewNativeACLIdentityCapture(context.Background())
	if runtime.GOOS == "darwin" {
		if err != nil || c == nil {
			t.Fatal(err)
		}
	} else if !errors.Is(err, errors.ErrUnsupported) || c != nil {
		t.Fatal(c, err)
	}
}
