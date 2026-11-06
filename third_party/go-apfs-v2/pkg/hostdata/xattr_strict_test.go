package hostdata

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStrictXattrInvalidInputs(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "input")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, name := range []string{"", "bad\x00name"} {
		if _, _, err := XattrSize(f, name); !errors.Is(err, os.ErrInvalid) {
			t.Fatal(err)
		}
		if _, _, err := ReadXattr(f, name, 1); !errors.Is(err, os.ErrInvalid) {
			t.Fatal(err)
		}
		if _, err := RemoveXattr(f, name); !errors.Is(err, os.ErrInvalid) {
			t.Fatal(err)
		}
		if _, _, err := XattrSizeNoFollow(f.Name(), name); !errors.Is(err, os.ErrInvalid) {
			t.Fatal(err)
		}
		if _, _, err := ReadXattrNoFollow(f.Name(), name, 1); !errors.Is(err, os.ErrInvalid) {
			t.Fatal(err)
		}
		if _, err := RemoveXattrNoFollow(f.Name(), name); !errors.Is(err, os.ErrInvalid) {
			t.Fatal(err)
		}
	}
	for _, limit := range []int{-1, MaxXattrReadSize + 1} {
		if _, _, err := ReadXattr(f, "user.test", limit); !errors.Is(err, os.ErrInvalid) {
			t.Fatal(err)
		}
		if _, _, err := ReadXattrNoFollow(f.Name(), "user.test", limit); !errors.Is(err, os.ErrInvalid) {
			t.Fatal(err)
		}
	}
	if _, _, err := XattrSize(nil, "user.test"); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if _, _, err := ReadXattr(nil, "user.test", 1); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := RemoveXattr(nil, "user.test"); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, present, err := XattrSize(f, "user.test"); present || err == nil {
		t.Fatal(present, err)
	}
	if data, present, err := ReadXattr(f, "user.test", 1); data != nil || present || err == nil {
		t.Fatal(data, present, err)
	}
	if removed, err := RemoveXattr(f, "user.test"); removed || err == nil {
		t.Fatal(removed, err)
	}
}

// These deterministic backend failures exercise the allocation and two-call
// protocol; real host integration below tests the syscall adapters themselves.
func TestStrictXattrReadProtocol(t *testing.T) {
	for _, tc := range []struct {
		name                string
		size, read, limit   int
		first, second, want error
		calls               int
	}{
		{"value", 4, 4, 4, nil, nil, nil, 2},
		{"empty", 0, 0, 0, nil, nil, nil, 2},
		{"empty-grown", 0, 1, 0, nil, nil, ErrXattrChanged, 2},
		{"shrunk", 4, 3, 4, nil, nil, ErrXattrChanged, 2},
		{"invalid-size", -1, 0, 4, nil, nil, ErrXattrChanged, 1},
		{"too-large", MaxXattrReadSize + 1, 0, MaxXattrReadSize, nil, nil, ErrXattrTooLarge, 1},
		{"caller-limit", 4, 0, 3, nil, nil, ErrXattrTooLarge, 1},
		{"query-denied", 0, 0, 4, os.ErrPermission, nil, os.ErrPermission, 1},
		{"read-denied", 4, 0, 4, nil, os.ErrPermission, os.ErrPermission, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			data, present, err := readVisibleXattr(func(buf []byte) (int, error) {
				calls++
				if calls == 1 {
					if buf != nil {
						t.Fatal("size query allocated")
					}
					return tc.size, tc.first
				}
				if len(buf) != max(tc.size, 1) {
					t.Fatal("allocation size", len(buf), tc.size)
				}
				copy(buf, "data")
				return tc.read, tc.second
			}, tc.limit)
			if calls != tc.calls || !errors.Is(err, tc.want) || present != (tc.want == nil) {
				t.Fatal(calls, present, err)
			}
			if tc.want != nil && data != nil {
				t.Fatal("returned partial data")
			}
			if tc.want == nil && (data == nil || len(data) != tc.read || !bytes.Equal(data, []byte("data")[:tc.read])) {
				t.Fatal(data)
			}
		})
	}
	if removed, err := removeVisibleXattr(func() error { return os.ErrPermission }); removed || !errors.Is(err, os.ErrPermission) {
		t.Fatal(removed, err)
	}
	if removed, err := removeVisibleXattr(func() error { return nil }); !removed || err != nil {
		t.Fatal(removed, err)
	}
}

func TestStrictXattrHostSupport(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "input")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	path := f.Name()
	if XattrsSupported || runtime.GOOS == "windows" {
		path = filepath.Join(t.TempDir(), "absent")
		if _, _, err := XattrSizeNoFollow(path, "user.test"); !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if _, _, err := ReadXattrNoFollow(path, "user.test", 1); !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if _, err := RemoveXattrNoFollow(path, "user.test"); !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		return
	}
	if _, present, err := XattrSize(f, "user.test"); present || !errors.Is(err, ErrXattrUnsupported) {
		t.Fatal(present, err)
	}
	if data, present, err := ReadXattr(f, "user.test", 1); data != nil || present || !errors.Is(err, ErrXattrUnsupported) {
		t.Fatal(data, present, err)
	}
	if removed, err := RemoveXattr(f, "user.test"); removed || !errors.Is(err, ErrXattrUnsupported) {
		t.Fatal(removed, err)
	}
	if _, present, err := XattrSizeNoFollow(path, "user.test"); present || !errors.Is(err, ErrXattrUnsupported) {
		t.Fatal(present, err)
	}
	if data, present, err := ReadXattrNoFollow(path, "user.test", 1); data != nil || present || !errors.Is(err, ErrXattrUnsupported) {
		t.Fatal(data, present, err)
	}
	if removed, err := RemoveXattrNoFollow(path, "user.test"); removed || !errors.Is(err, ErrXattrUnsupported) {
		t.Fatal(removed, err)
	}
}
