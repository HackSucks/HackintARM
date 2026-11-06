//go:build linux || darwin

// A FUSE file system over any VolumeFS, so mounting works for every file
// system this tool reads rather than only APFS.
//
// The APFS-specific mount in mount_fuse.go reaches into *apfs.FileEntry
// directly, which is why HFS+ could not be mounted at all. Everything FUSE
// actually needs -- stat, readdir, open, read, readlink, extended attributes --
// is already in VolumeFS and XattrVolume, so this serves whichever volume the
// image turned out to hold.
package tools

import (
	"context"
	"fmt"
	"hash/fnv"
	"io"
	iofs "io/fs"
	"path"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// attrTimeout is how long the kernel may cache an attribute or directory
// entry. The image is read-only and cannot change underneath us, so this is
// generous rather than conservative.
const attrTimeout = time.Hour

// volumeNode is one file or directory in the mounted volume, identified by its
// io/fs path ("." for the root).
type volumeNode struct {
	fs.Inode
	vol  VolumeFS
	path string
}

var (
	_ fs.NodeGetattrer   = (*volumeNode)(nil)
	_ fs.NodeLookuper    = (*volumeNode)(nil)
	_ fs.NodeReaddirer   = (*volumeNode)(nil)
	_ fs.NodeOpener      = (*volumeNode)(nil)
	_ fs.NodeReadlinker  = (*volumeNode)(nil)
	_ fs.NodeGetxattrer  = (*volumeNode)(nil)
	_ fs.NodeListxattrer = (*volumeNode)(nil)
)

// inodeNumber derives a stable inode number from a path. FUSE requires the
// same path to keep the same number for as long as it is mounted, and a hash
// gives that without tracking every path seen. Collisions are possible in
// principle and harmless in practice: the kernel uses the number to recognize
// a node it already holds, and lookups are always by name.
func inodeNumber(p string) uint64 {
	if p == "." {
		return 1 // the root is conventionally inode 1
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(p))
	n := h.Sum64()
	if n <= 1 {
		n += 2 // keep clear of the root
	}
	return n
}

// fileModeToFUSE converts an io/fs mode to the st_mode a FUSE reply needs.
func fileModeToFUSE(mode iofs.FileMode) uint32 {
	out := uint32(mode.Perm())
	switch {
	case mode.IsDir():
		out |= syscall.S_IFDIR
	case mode&iofs.ModeSymlink != 0:
		out |= syscall.S_IFLNK
	case mode&iofs.ModeCharDevice != 0:
		out |= syscall.S_IFCHR
	case mode&iofs.ModeDevice != 0:
		out |= syscall.S_IFBLK
	case mode&iofs.ModeNamedPipe != 0:
		out |= syscall.S_IFIFO
	case mode&iofs.ModeSocket != 0:
		out |= syscall.S_IFSOCK
	default:
		out |= syscall.S_IFREG
	}
	return out
}

func fillAttr(attr *fuse.Attr, p string, info iofs.FileInfo) {
	attr.Ino = inodeNumber(p)
	attr.Mode = fileModeToFUSE(info.Mode())
	attr.Size = uint64(info.Size())
	attr.Blocks = (attr.Size + 511) / 512
	attr.Nlink = 1
	if modTime := info.ModTime(); !modTime.IsZero() {
		secs := uint64(modTime.Unix())
		attr.Atime, attr.Mtime, attr.Ctime = secs, secs, secs
	}
}

func (n *volumeNode) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	info, err := n.vol.Stat(n.path)
	if err != nil {
		return syscall.ENOENT
	}
	fillAttr(&out.Attr, n.path, info)
	out.SetTimeout(attrTimeout)
	return 0
}

func (n *volumeNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	child := name
	if n.path != "." {
		child = path.Join(n.path, name)
	}

	info, err := n.vol.Stat(child)
	if err != nil {
		return nil, syscall.ENOENT
	}

	stable := fs.StableAttr{
		Mode: fileModeToFUSE(info.Mode()) &^ 0o7777,
		Ino:  inodeNumber(child),
	}
	inode := n.NewInode(ctx, &volumeNode{vol: n.vol, path: child}, stable)

	fillAttr(&out.Attr, child, info)
	out.SetEntryTimeout(attrTimeout)
	out.SetAttrTimeout(attrTimeout)
	return inode, 0
}

func (n *volumeNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	entries, err := n.vol.ReadDir(n.path)
	if err != nil {
		return nil, syscall.EIO
	}

	out := make([]fuse.DirEntry, 0, len(entries))
	for _, e := range entries {
		child := e.Name()
		if n.path != "." {
			child = path.Join(n.path, e.Name())
		}
		out = append(out, fuse.DirEntry{
			Name: e.Name(),
			Mode: fileModeToFUSE(e.Type()) &^ 0o7777,
			Ino:  inodeNumber(child),
		})
	}
	return fs.NewListDirStream(out), 0
}

func (n *volumeNode) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	target, err := n.vol.Readlink(n.path)
	if err != nil {
		return nil, syscall.EINVAL
	}
	return []byte(target), 0
}

func (n *volumeNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	// Read-only: anything asking to write is refused rather than silently
	// accepted and then failing at write time.
	if flags&(syscall.O_WRONLY|syscall.O_RDWR|syscall.O_APPEND|syscall.O_TRUNC|syscall.O_CREAT) != 0 {
		return nil, 0, syscall.EROFS
	}

	file, err := n.vol.Open(n.path)
	if err != nil {
		return nil, 0, syscall.ENOENT
	}
	return &volumeHandle{vol: n.vol, path: n.path, file: file}, fuse.FOPEN_KEEP_CACHE, 0
}

func (n *volumeNode) xattrs() (map[string][]byte, syscall.Errno) {
	source, ok := n.vol.(XattrVolume)
	if !ok {
		return nil, syscall.ENOTSUP
	}
	attrs, err := source.Xattrs(n.path)
	if err != nil {
		return nil, syscall.EIO
	}
	return attrs, 0
}

func (n *volumeNode) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	attrs, errno := n.xattrs()
	if errno != 0 {
		return 0, errno
	}
	value, ok := attrs[attr]
	if !ok {
		return 0, fs.ENOATTR
	}
	// A zero-length request is how a caller asks for the size first.
	if len(dest) < len(value) {
		return uint32(len(value)), syscall.ERANGE
	}
	return uint32(copy(dest, value)), 0
}

func (n *volumeNode) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
	attrs, errno := n.xattrs()
	if errno != 0 {
		return 0, errno
	}
	// The reply is NUL-terminated names run together.
	var buf []byte
	for name := range attrs {
		buf = append(buf, name...)
		buf = append(buf, 0)
	}
	if len(dest) < len(buf) {
		return uint32(len(buf)), syscall.ERANGE
	}
	return uint32(copy(dest, buf)), 0
}

// volumeHandle is one open file. Reads go through io.ReaderAt when the volume
// offers it, which both readers do; the fallback exists so a VolumeFS that
// only supports sequential reads still works.
//
// The mutex is not an optimisation detail. FUSE issues reads for one file
// handle in parallel, and neither reader is safe for that: a file entry funnels
// every read through a single data stream that carries its own current offset,
// and the decompressing reader saves and restores that offset around each read.
// Concurrent reads therefore interleave and return the wrong bytes -- visible
// only on a file large enough for the kernel to split into several reads, which
// is why a real mount caught it and the unit tests did not.
type volumeHandle struct {
	vol  VolumeFS
	path string
	file iofs.File

	mu       sync.Mutex
	fallback []byte // whole-file contents, read once, only when needed
}

var (
	_ fs.FileReader   = (*volumeHandle)(nil)
	_ fs.FileReleaser = (*volumeHandle)(nil)
)

func (h *volumeHandle) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if readerAt, ok := h.file.(io.ReaderAt); ok {
		n, err := readerAt.ReadAt(dest, off)
		if err != nil && err != io.EOF {
			return nil, syscall.EIO
		}
		return fuse.ReadResultData(dest[:n]), 0
	}

	if h.fallback == nil {
		data, err := h.vol.ReadFile(h.path)
		if err != nil {
			return nil, syscall.EIO
		}
		h.fallback = data
	}
	if off >= int64(len(h.fallback)) {
		return fuse.ReadResultData(nil), 0
	}
	return fuse.ReadResultData(h.fallback[off:]), 0
}

func (h *volumeHandle) Release(ctx context.Context) syscall.Errno {
	if h.file != nil {
		h.file.Close()
	}
	return 0
}

// MountVolumeFS mounts any VolumeFS read-only at mountPoint. name appears in
// the mount table and in df output.
func MountVolumeFS(volume VolumeFS, name, mountPoint string, debug bool) (MountServer, error) {
	if volume == nil {
		return nil, fmt.Errorf("no volume to mount")
	}

	root := &volumeNode{vol: volume, path: "."}
	options := &fs.Options{
		MountOptions: fuse.MountOptions{
			Name:       name,
			FsName:     name,
			Debug:      debug,
			AllowOther: false,
		},
	}
	options.AttrTimeout = &[]time.Duration{attrTimeout}[0]
	options.EntryTimeout = &[]time.Duration{attrTimeout}[0]

	server, err := fs.Mount(mountPoint, root, options)
	if err != nil {
		return nil, fmt.Errorf("unable to mount: %w", err)
	}
	return server, nil
}
