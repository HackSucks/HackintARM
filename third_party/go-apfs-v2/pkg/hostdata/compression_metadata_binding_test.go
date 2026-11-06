package hostdata

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestCompressionMetadataHeldProviderBinding(t *testing.T) {
	f, e := os.CreateTemp(t.TempDir(), "held-query-")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	wantFD := int(f.Fd())
	check := func(fd int) {
		t.Helper()
		if fd != wantFD {
			t.Fatal("redirected held descriptor", fd, wantFD)
		}
	}
	stats, attrs := 0, 0
	stat := func(fd int) (uint32, uint64, error) { check(fd); stats++; return UFCompressed, 65536, nil }
	get := func(fd int, name string, p []byte) (int, error) {
		check(fd)
		attrs++
		if name == ResourceForkName {
			if p != nil {
				t.Fatal("read fork payload")
			}
			return 100, nil
		}
		if name != DecmpfsName {
			t.Fatal("unrelated attribute", name)
		}
		if p == nil {
			return 24, nil
		}
		return copy(p, compressionMetadataHeader(8)), nil
	}
	info, e := queryCompressionUsing(t.Context(), f, 24, stat, get)
	if e != nil || info.Type != 8 || info.StoredSize != 124 || info.LogicalSize != 65536 || stats != 2 || attrs != 3 {
		t.Fatal(info, e, stats, attrs)
	}
	flags, e := compressionVolumeFlagsUsing(t.Context(), f, func(fd int) (uint32, error) { check(fd); return 0x80, nil })
	if e != nil || flags != 0x80 {
		t.Fatal(flags, e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	flags, e = compressionVolumeFlagsUsing(ctx, f, func(fd int) (uint32, error) { check(fd); cancel(); return 0x80, nil })
	if flags != 0 || !errors.Is(e, context.Canceled) {
		t.Fatal("late cancellation exposed partial result", flags, e)
	}
	if _, e = f.Stat(); e != nil {
		t.Fatal("closed caller-owned handle", e)
	}
}
