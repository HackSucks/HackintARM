package hostdata

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestNativeCompressionOwnedValidation(t *testing.T) {
	if _, err := NewNativeCompressionInput(t.Context(), nil); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(t.TempDir(), "owned-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = NewNativeCompressionInput(ctx, f); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err = f.Stat(); err != nil {
		t.Fatal("constructor failure closed caller file", err)
	}
}

func TestCompressionVolumeObservation(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "volume-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	marker := errors.New("volume observation failed")
	for _, tc := range []struct {
		name   string
		value  CompressionVolume
		fail   error
		cancel bool
	}{
		{"apfs", CompressionVolume{"apfs", 0x80}, nil, false},
		{"hfs", CompressionVolume{"hfs", 0}, nil, false},
		{"unknown-observed", CompressionVolume{"other-filesystem", 0xffffffff}, nil, false},
		{"native-failure", CompressionVolume{}, marker, false},
		{"late-cancellation", CompressionVolume{"apfs", 0x80}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			got, err := queryCompressionVolumeUsing(ctx, f, func(fd int) (CompressionVolume, error) {
				calls++
				if fd != int(f.Fd()) {
					t.Fatal("not held descriptor")
				}
				if tc.cancel {
					cancel()
				}
				return tc.value, tc.fail
			})
			if calls != 1 {
				t.Fatal("expected exactly one volume observation", calls)
			}
			switch {
			case tc.cancel:
				if !errors.Is(err, context.Canceled) || got != (CompressionVolume{}) {
					t.Fatal(got, err)
				}
			case tc.fail != nil:
				if !errors.Is(err, tc.fail) || got != (CompressionVolume{}) {
					t.Fatal(got, err)
				}
			default:
				if err != nil || got != tc.value {
					t.Fatal(got, err)
				}
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = queryCompressionVolumeUsing(ctx, f, func(int) (CompressionVolume, error) {
		t.Fatal("observed after cancellation")
		return CompressionVolume{}, nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err = QueryCompressionVolume(t.Context(), nil); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	conn, e := f.SyscallConn()
	if e != nil {
		t.Fatal(e)
	}
	closed := conn.Control(func(uintptr) { t.Fatal("closed descriptor observed") })
	if closed == nil {
		t.Fatal("closed control succeeded")
	}
	if _, err = QueryCompressionVolume(t.Context(), f); !errors.Is(err, closed) {
		t.Fatal(err)
	}
}
