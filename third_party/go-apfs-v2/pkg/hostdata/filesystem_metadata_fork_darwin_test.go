package hostdata

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestFilesystemMetadataNativeForkStreaming(t *testing.T) {
	v, _, _ := newMetadataTestView(t, false)
	ctx := context.Background()
	if err := SetXattr(v.file, ResourceForkName, []byte("native-value")); err != nil {
		t.Fatal(err)
	}
	for _, fs := range []string{"exfat", "msdos"} {
		value, err := nativeFilesystemResourceUsing(ctx, v.file, func(int) (string, error) { return fs, nil }, unix.Dup)
		if err != nil {
			t.Fatal(err)
		}
		if value.Size() != 12 {
			t.Fatal(value.Size())
		}
		b := make([]byte, 20)
		if n, err := value.ReadAt(b, 7); n != 5 || !errors.Is(err, io.EOF) || string(b[:n]) != "value" {
			t.Fatal(n, err, string(b))
		}
		if n, err := value.ReadAt(b, 12); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatal(n, err)
		}
		if n, err := value.ReadAt(nil, 0); n != 0 || err != nil {
			t.Fatal(n, err)
		}
		if err = value.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if value, err := nativeFilesystemResource(ctx, v.file); err != nil || value != nil {
		t.Fatal(value, err)
	}
	fail := func(int) (string, error) { return "", io.ErrUnexpectedEOF }
	if _, err := nativeFilesystemResourceUsing(ctx, v.file, fail, unix.Dup); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	volume := func(int) (string, error) { return "exfat", nil }
	if _, err := nativeFilesystemResourceUsing(ctx, v.file, volume, func(int) (int, error) { return -1, os.ErrPermission }); !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := nativeFilesystemResourceUsing(canceled, v.file, volume, unix.Dup); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	value, err := nativeFilesystemResourceUsing(ctx, v.file, volume, unix.Dup)
	if err != nil {
		t.Fatal(err)
	}
	defer value.Close()
	native := value.value.(*filesystemNativeFork)
	if _, err := native.ReadAt(make([]byte, 1), -1); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	native.read = func(int, []byte, uint32) (int, error) { return 0, nil }
	if _, err := native.ReadAt(make([]byte, 1), 0); !errors.Is(err, ErrXattrChanged) {
		t.Fatal(err)
	}
	native.read = func(int, []byte, uint32) (int, error) { return 0, os.ErrPermission }
	if _, err := native.ReadAt(make([]byte, 1), 0); !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	if _, err := RemoveXattr(v.file, ResourceForkName); err != nil {
		t.Fatal(err)
	}
	if _, err := native.ReadAt(make([]byte, 1), 0); !errors.Is(err, ErrXattrChanged) {
		t.Fatal(err)
	}
	if _, err := nativeFilesystemResourceUsing(ctx, v.file, volume, unix.Dup); !errors.Is(err, ErrXattrChanged) {
		t.Fatal(err)
	}
	if err := native.file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := native.ReadAt(make([]byte, 1), 0); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}

func TestFilesystemMetadataForkWrapperFailures(t *testing.T) {
	saved := loadDarwinXattr
	t.Cleanup(func() { loadDarwinXattr = saved })
	loadDarwinXattr = func() (*darwinXattrABI, error) { return nil, io.ErrClosedPipe }
	if _, err := darwinFilesystemForkRead(0, make([]byte, 1), 0); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
}
