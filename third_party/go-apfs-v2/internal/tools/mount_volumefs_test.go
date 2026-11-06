//go:build linux || darwin

package tools

import (
	"context"
	"io"
	iofs "io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// These exercise the FUSE translation layer against a real volume without
// mounting anything: every method here is callable directly. Lookup is the
// exception, since it allocates an inode in a live tree, so an end-to-end check
// needs FUSE and belongs where FUSE exists.

func fixtureVolume(t *testing.T) VolumeFS {
	t.Helper()
	image := filepath.Join("..", "..", "testdata", "cli", "hfs-basic.dmg")
	if _, err := os.Stat(image); err != nil {
		t.Skipf("fixture image missing: %v", err)
	}
	reader, offset, closer, err := disk.OpenWithOffset(image)
	if err != nil {
		t.Fatalf("opening the fixture: %v", err)
	}
	t.Cleanup(func() { closer.Close() })

	var device io.ReaderAt = reader
	if offset != 0 {
		device = io.NewSectionReader(reader, offset, 1<<62)
	}
	volume, err := hfsplus.New(device)
	if err != nil {
		t.Fatalf("parsing the fixture: %v", err)
	}
	return volume
}

func TestMountNodeGetattr(t *testing.T) {
	vol := fixtureVolume(t)
	ctx := context.Background()

	root := &volumeNode{vol: vol, path: "."}
	var out fuse.AttrOut
	if errno := root.Getattr(ctx, nil, &out); errno != 0 {
		t.Fatalf("Getattr on the root: errno %v", errno)
	}
	if out.Attr.Mode&syscall.S_IFDIR == 0 {
		t.Errorf("root mode %#o is not a directory", out.Attr.Mode)
	}
	if out.Attr.Ino != 1 {
		t.Errorf("root inode = %d, want 1", out.Attr.Ino)
	}

	file := &volumeNode{vol: vol, path: "hello.txt"}
	out = fuse.AttrOut{}
	if errno := file.Getattr(ctx, nil, &out); errno != 0 {
		t.Fatalf("Getattr on a file: errno %v", errno)
	}
	if out.Attr.Mode&syscall.S_IFREG == 0 {
		t.Errorf("file mode %#o is not a regular file", out.Attr.Mode)
	}
	if out.Attr.Size == 0 {
		t.Error("file size is 0")
	}

	missing := &volumeNode{vol: vol, path: "no-such-file"}
	if errno := missing.Getattr(ctx, nil, &fuse.AttrOut{}); errno != syscall.ENOENT {
		t.Errorf("Getattr on a missing path = %v, want ENOENT", errno)
	}
}

func TestMountNodeReaddir(t *testing.T) {
	vol := fixtureVolume(t)

	root := &volumeNode{vol: vol, path: "."}
	stream, errno := root.Readdir(context.Background())
	if errno != 0 {
		t.Fatalf("Readdir: errno %v", errno)
	}

	seen := map[string]fuse.DirEntry{}
	for stream.HasNext() {
		e, errno := stream.Next()
		if errno != 0 {
			t.Fatalf("Next: errno %v", errno)
		}
		seen[e.Name] = e
	}

	for _, want := range []string{"hello.txt", "dir1", "link-to-hello"} {
		if _, ok := seen[want]; !ok {
			t.Errorf("Readdir did not report %q", want)
		}
	}
	if e := seen["dir1"]; e.Mode&syscall.S_IFDIR == 0 {
		t.Errorf("dir1 mode %#o is not a directory", e.Mode)
	}
	if e := seen["link-to-hello"]; e.Mode&syscall.S_IFLNK == 0 {
		t.Errorf("link-to-hello mode %#o is not a symlink", e.Mode)
	}
	// Every entry needs a distinct, non-zero inode number, or the kernel
	// conflates them.
	inodes := map[uint64]string{}
	for name, e := range seen {
		if e.Ino == 0 {
			t.Errorf("%s has inode 0", name)
		}
		if prev, clash := inodes[e.Ino]; clash {
			t.Errorf("%s and %s share inode %d", name, prev, e.Ino)
		}
		inodes[e.Ino] = name
	}
}

func TestMountNodeOpenAndRead(t *testing.T) {
	vol := fixtureVolume(t)
	ctx := context.Background()

	node := &volumeNode{vol: vol, path: "hello.txt"}
	handle, _, errno := node.Open(ctx, uint32(os.O_RDONLY))
	if errno != 0 {
		t.Fatalf("Open: errno %v", errno)
	}
	reader, ok := handle.(*volumeHandle)
	if !ok {
		t.Fatalf("Open returned %T, want *volumeHandle", handle)
	}
	defer reader.Release(ctx)

	want, err := vol.ReadFile("hello.txt")
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, len(want))
	result, errno := reader.Read(ctx, buf, 0)
	if errno != 0 {
		t.Fatalf("Read: errno %v", errno)
	}
	got, status := result.Bytes(buf)
	if !status.Ok() {
		t.Fatalf("read result status %v", status)
	}
	if string(got) != string(want) {
		t.Errorf("read %q, want %q", got, want)
	}

	// Reading from an offset must not restart at the beginning.
	if len(want) > 4 {
		part := make([]byte, len(want)-4)
		result, errno = reader.Read(ctx, part, 4)
		if errno != 0 {
			t.Fatalf("Read at offset: errno %v", errno)
		}
		got, _ = result.Bytes(part)
		if string(got) != string(want[4:]) {
			t.Errorf("read at offset 4 = %q, want %q", got, want[4:])
		}
	}
}

func TestMountNodeRefusesWrites(t *testing.T) {
	vol := fixtureVolume(t)
	node := &volumeNode{vol: vol, path: "hello.txt"}

	for name, flags := range map[string]uint32{
		"O_WRONLY": uint32(os.O_WRONLY),
		"O_RDWR":   uint32(os.O_RDWR),
		"O_TRUNC":  uint32(os.O_RDWR | os.O_TRUNC),
	} {
		if _, _, errno := node.Open(context.Background(), flags); errno != syscall.EROFS {
			t.Errorf("Open with %s = %v, want EROFS", name, errno)
		}
	}
}

func TestMountNodeReadlink(t *testing.T) {
	vol := fixtureVolume(t)

	node := &volumeNode{vol: vol, path: "link-to-hello"}
	target, errno := node.Readlink(context.Background())
	if errno != 0 {
		t.Fatalf("Readlink: errno %v", errno)
	}
	if string(target) != "hello.txt" {
		t.Errorf("Readlink = %q, want %q", target, "hello.txt")
	}

	// A regular file is not a symlink.
	notLink := &volumeNode{vol: vol, path: "hello.txt"}
	if _, errno := notLink.Readlink(context.Background()); errno != syscall.EINVAL {
		t.Errorf("Readlink on a regular file = %v, want EINVAL", errno)
	}
}

func TestMountNodeXattrs(t *testing.T) {
	vol := fixtureVolume(t)
	ctx := context.Background()
	node := &volumeNode{vol: vol, path: "hello.txt"}

	// A short buffer must report the size it needs rather than truncating,
	// which is how getxattr(2) is asked for a size.
	size, errno := node.Getxattr(ctx, "com.apple.provenance", nil)
	if errno != syscall.ERANGE {
		t.Fatalf("Getxattr with no buffer = %v, want ERANGE", errno)
	}
	if size == 0 {
		t.Fatal("Getxattr reported size 0 for an attribute that exists")
	}

	buf := make([]byte, size)
	got, errno := node.Getxattr(ctx, "com.apple.provenance", buf)
	if errno != 0 {
		t.Fatalf("Getxattr: errno %v", errno)
	}
	if got != size {
		t.Errorf("Getxattr returned %d bytes, want %d", got, size)
	}

	if _, errno := node.Getxattr(ctx, "com.example.absent", make([]byte, 64)); errno == 0 {
		t.Error("Getxattr for a missing attribute succeeded")
	}

	// Listxattr returns NUL-terminated names run together.
	listSize, errno := node.Listxattr(ctx, nil)
	if errno != syscall.ERANGE {
		t.Fatalf("Listxattr with no buffer = %v, want ERANGE", errno)
	}
	list := make([]byte, listSize)
	if _, errno := node.Listxattr(ctx, list); errno != 0 {
		t.Fatalf("Listxattr: errno %v", errno)
	}
	names := strings.Split(strings.TrimRight(string(list), "\x00"), "\x00")
	found := false
	for _, n := range names {
		if n == "com.apple.provenance" {
			found = true
		}
	}
	if !found {
		t.Errorf("Listxattr = %v, want com.apple.provenance among them", names)
	}
}

func TestInodeNumberIsStableAndDistinct(t *testing.T) {
	if inodeNumber(".") != 1 {
		t.Error("the root must be inode 1")
	}
	if first, second := inodeNumber("a/b.txt"), inodeNumber("a/b.txt"); first != second {
		t.Error("the same path produced different inode numbers")
	}
	if inodeNumber("a/b.txt") == inodeNumber("a/c.txt") {
		t.Error("different paths produced the same inode number")
	}
	for _, p := range []string{"a", "b", "dir/file", "x/y/z"} {
		if inodeNumber(p) <= 1 {
			t.Errorf("%q produced inode %d, which collides with the root", p, inodeNumber(p))
		}
	}
}

func TestFileModeToFUSE(t *testing.T) {
	for _, tc := range []struct {
		mode iofs.FileMode
		want uint32
	}{
		{0o644, syscall.S_IFREG | 0o644},
		{iofs.ModeDir | 0o755, syscall.S_IFDIR | 0o755},
		{iofs.ModeSymlink | 0o777, syscall.S_IFLNK | 0o777},
		{iofs.ModeNamedPipe | 0o600, syscall.S_IFIFO | 0o600},
		{iofs.ModeSocket | 0o600, syscall.S_IFSOCK | 0o600},
	} {
		if got := fileModeToFUSE(tc.mode); got != tc.want {
			t.Errorf("fileModeToFUSE(%v) = %#o, want %#o", tc.mode, got, tc.want)
		}
	}
}
