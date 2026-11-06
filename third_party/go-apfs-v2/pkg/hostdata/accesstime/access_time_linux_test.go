package accesstime

import (
	"errors"
	"os"
	"syscall"
	"testing"
	"time"

	heldfixture "github.com/deploymenttheory/go-apfs-v2/internal/testutil/heldfixture"
)

func TestCarrierLinuxAccessTime(t *testing.T) {
	source, target := heldfixture.Source(t, 0600), heldfixture.Source(t, 0600)
	when := time.Unix(978307200, 234567891)
	if err := os.Chtimes(source.Name(), when, when.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	from, err := source.Stat()
	if err != nil {
		t.Fatal(err)
	}
	before, err := target.Stat()
	if err != nil {
		t.Fatal(err)
	}
	name := target.Name()
	if err := os.Rename(name, name+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("decoy"), 0600); err != nil {
		t.Fatal(err)
	}
	decoy, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := CopyAccessTime(source, target); err != nil {
		t.Fatal(err)
	}
	after, err := target.Stat()
	if err != nil {
		t.Fatal(err)
	}
	want, got := *before.Sys().(*syscall.Stat_t), *after.Sys().(*syscall.Stat_t)
	if got.Atim != from.Sys().(*syscall.Stat_t).Atim {
		t.Fatal("access time differs")
	}
	want.Atim, want.Ctim = got.Atim, got.Ctim
	if want != got {
		t.Fatal("unrelated target metadata changed")
	}
	afterSource, err := source.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if *from.Sys().(*syscall.Stat_t) != *afterSource.Sys().(*syscall.Stat_t) {
		t.Fatal("source changed")
	}
	afterDecoy, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	if *decoy.Sys().(*syscall.Stat_t) != *afterDecoy.Sys().(*syscall.Stat_t) {
		t.Fatal("decoy changed")
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	if err := copyAccessTime(target, from); err == nil {
		t.Fatalf("closed: %v", err)
	}
	if err := copyAccessTime(nil, from); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nil: %v", err)
	}
}
