package hostdata

import (
	"errors"
	"os"
	"testing"

	heldfixture "github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"golang.org/x/sys/unix"
)

func TestPathResourceForkNative(t *testing.T) {
	f := heldfixture.Source(t, 0600)
	if e := SetXattr(f, appledouble.ResourceForkName, []byte("fork")); e != nil {
		t.Fatal(e)
	}
	p := &appleDoublePath{}
	a, e := p.openFork(f, false)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.Close(); e != nil {
		t.Fatal(e)
	}
	b, e := p.openFork(f, true)
	if e != nil {
		t.Fatal(e)
	}
	if e = b.Close(); e != nil {
		t.Fatal(e)
	}
	if _, present, e := ReadXattr(f, appledouble.ResourceForkName, 32); e != nil || present {
		t.Fatal(present, e)
	}
	if _, e := openPathResourceForkNative(nil, false, 0); e == nil {
		t.Fatal("nil accepted")
	}
	marker := errors.New("native fork failure")
	if _, e := openPathResourceForkUsing(f, false, 0600, func(int, string, int, uint32) (int, error) { return -1, marker }, nil); !errors.Is(e, marker) {
		t.Fatal(e)
	}
	if e := SetXattr(f, appledouble.ResourceForkName, []byte("fork")); e != nil {
		t.Fatal(e)
	}
	var owned *os.File
	if _, e := openPathResourceForkUsing(f, false, 0600, unix.Openat, func(v *os.File) (os.FileInfo, error) { owned = v; return nil, marker }); !errors.Is(e, marker) {
		t.Fatal(e)
	}
	if _, e := owned.Stat(); !errors.Is(e, os.ErrClosed) {
		t.Fatal("failed stat leaked fork", e)
	}
}
