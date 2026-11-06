// io/fs adapter: Volume implements fs.FS, fs.ReadDirFS, fs.StatFS and
// fs.ReadFileFS, so volumes can be walked with fs.WalkDir, tested with
// testing/fstest and passed to anything that consumes an fs.FS.
//
// Symlinks are never followed: Stat and Open return the link itself, like
// archive-backed filesystems. Use Readlink to resolve targets.
package hfsplus

import (
	"fmt"
	"io"
	"io/fs"
	"path"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/unixmode"
)

var (
	_ fs.FS         = (*Volume)(nil)
	_ fs.ReadDirFS  = (*Volume)(nil)
	_ fs.StatFS     = (*Volume)(nil)
	_ fs.ReadFileFS = (*Volume)(nil)
)

// entryByFSName resolves an fs.FS path ("." or "a/b/c") to an entry.
func (v *Volume) entryByFSName(op, name string) (*entry, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: op, Path: name, Err: fs.ErrInvalid}
	}

	e, err := v.lookup(name)
	if err != nil {
		return nil, &fs.PathError{Op: op, Path: name, Err: fmt.Errorf("%w: %v", fs.ErrNotExist, err)}
	}

	return e, nil
}

// Open implements fs.FS.
func (v *Volume) Open(name string) (fs.File, error) {
	e, err := v.entryByFSName("open", name)
	if err != nil {
		return nil, err
	}

	info := v.newFileInfo(path.Base(name), e)

	if e.isDir {
		return &hfsDir{volume: v, name: name, info: info}, nil
	}

	fork, err := v.dataForkReader(e)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}

	return &hfsFile{fork: fork, info: info}, nil
}

// ReadDir implements fs.ReadDirFS. Entries are sorted by filename as the
// interface requires.
func (v *Volume) ReadDir(name string) ([]fs.DirEntry, error) {
	e, err := v.entryByFSName("readdir", name)
	if err != nil {
		return nil, err
	}
	if !e.isDir {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fmt.Errorf("not a directory")}
	}

	entries := make([]fs.DirEntry, 0, len(e.children))
	for _, child := range e.children {
		entries = append(entries, dirEntry{info: v.newFileInfo(posixName(child.name), child)})
	}

	return entries, nil
}

// Stat implements fs.StatFS. Symlinks are not followed.
func (v *Volume) Stat(name string) (fs.FileInfo, error) {
	e, err := v.entryByFSName("stat", name)
	if err != nil {
		return nil, err
	}

	return v.newFileInfo(path.Base(name), e), nil
}

// ReadFile implements fs.ReadFileFS.
func (v *Volume) ReadFile(name string) ([]byte, error) {
	e, err := v.entryByFSName("readfile", name)
	if err != nil {
		return nil, err
	}

	fork, err := v.dataForkReader(e)
	if err != nil {
		return nil, &fs.PathError{Op: "readfile", Path: name, Err: err}
	}

	if fork.Size() == 0 {
		return []byte{}, nil
	}

	data := make([]byte, fork.Size())
	n, err := fork.ReadAt(data, 0)
	if err != nil && err != io.EOF {
		return nil, &fs.PathError{Op: "readfile", Path: name, Err: err}
	}

	return data[:n], nil
}

// Readlink returns the target of the symbolic link at name.
func (v *Volume) Readlink(name string) (string, error) {
	e, err := v.entryByFSName("readlink", name)
	if err != nil {
		return "", err
	}

	target, err := v.readlink(e)
	if err != nil {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: err}
	}

	return target, nil
}

// Xattrs returns the extended attributes of the file at name.
//
// A file's resource fork is reported as com.apple.ResourceFork, which is what
// macOS presents it as, even though HFS+ stores it as a fork of the catalog
// record rather than in the attributes file.
//
// com.apple.decmpfs is returned like any other attribute rather than being
// filtered out. A caller writing these attributes back onto a decompressed copy
// of the file must drop it, since it would describe content the copy no longer
// holds.
func (v *Volume) Xattrs(name string) (map[string][]byte, error) {
	e, err := v.entryByFSName("xattrs", name)
	if err != nil {
		return nil, err
	}

	attrs, err := v.xattrs(e)
	if err != nil {
		return nil, &fs.PathError{Op: "xattrs", Path: name, Err: err}
	}

	return attrs, nil
}

// fileInfo implements fs.FileInfo for HFS+ entries. Sys returns the
// *HFSPlusCatalogFile for files and *HFSPlusCatalogFolder for folders.
type fileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	sys     any
}

func (v *Volume) newFileInfo(name string, e *entry) *fileInfo {
	var bsd BSDInfo
	var modTime hfsTime
	var size int64
	var sys any

	if e.isDir {
		bsd = e.folder.BSDInfo
		modTime = e.folder.ContentModDate
		sys = e.folder
	} else if e.file != nil {
		bsd = e.file.BSDInfo
		modTime = e.file.ContentModDate
		size = v.logicalSize(e)
		sys = e.file
	}

	mode := unixmode.FilePermissions(bsd.FileMode)
	switch bsd.FileMode & sIFMT {
	case sIFDIR:
		mode |= fs.ModeDir
	case sIFLNK:
		mode |= fs.ModeSymlink
	case sIFCHR:
		mode |= fs.ModeDevice | fs.ModeCharDevice
	case sIFBLK:
		mode |= fs.ModeDevice
	case sIFIFO:
		mode |= fs.ModeNamedPipe
	case sIFSOCK:
		mode |= fs.ModeSocket
	}
	if e.isDir && mode&fs.ModeDir == 0 {
		// Volumes written without ownership info may leave FileMode zero;
		// the catalog record kind is authoritative for the type bit.
		mode |= fs.ModeDir
	}

	return &fileInfo{
		name:    name,
		size:    size,
		mode:    mode,
		modTime: modTime.Time(),
		sys:     sys,
	}
}

func (fi *fileInfo) Name() string       { return fi.name }
func (fi *fileInfo) Size() int64        { return fi.size }
func (fi *fileInfo) Mode() fs.FileMode  { return fi.mode }
func (fi *fileInfo) ModTime() time.Time { return fi.modTime }
func (fi *fileInfo) IsDir() bool        { return fi.mode.IsDir() }
func (fi *fileInfo) Sys() any           { return fi.sys }

// dirEntry implements fs.DirEntry.
type dirEntry struct {
	info *fileInfo
}

func (de dirEntry) Name() string               { return de.info.name }
func (de dirEntry) IsDir() bool                { return de.info.IsDir() }
func (de dirEntry) Type() fs.FileMode          { return de.info.mode.Type() }
func (de dirEntry) Info() (fs.FileInfo, error) { return de.info, nil }

// hfsFile implements fs.File, io.ReaderAt and io.Seeker for regular files
// and symlinks.
type hfsFile struct {
	fork   fileReader
	info   *fileInfo
	offset int64
}

func (f *hfsFile) Stat() (fs.FileInfo, error) { return f.info, nil }

func (f *hfsFile) Read(p []byte) (int, error) {
	n, err := f.ReadAt(p, f.offset)
	f.offset += int64(n)
	return n, err
}

func (f *hfsFile) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return f.fork.ReadAt(p, off)
}

func (f *hfsFile) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		offset += f.offset
	case io.SeekEnd:
		offset += f.fork.Size()
	default:
		return 0, fmt.Errorf("invalid whence: %d", whence)
	}
	if offset < 0 {
		return 0, fmt.Errorf("negative seek offset")
	}
	f.offset = offset
	return offset, nil
}

func (f *hfsFile) Close() error { return nil }

// hfsDir implements fs.ReadDirFile for directories.
type hfsDir struct {
	volume  *Volume
	name    string
	info    *fileInfo
	entries []fs.DirEntry
	read    int
}

func (d *hfsDir) Stat() (fs.FileInfo, error) { return d.info, nil }

func (d *hfsDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.name, Err: fmt.Errorf("is a directory")}
}

func (d *hfsDir) Close() error { return nil }

func (d *hfsDir) ReadDir(n int) ([]fs.DirEntry, error) {
	if d.entries == nil {
		entries, err := d.volume.ReadDir(d.name)
		if err != nil {
			return nil, err
		}
		d.entries = entries
	}

	remaining := d.entries[d.read:]
	if n <= 0 {
		d.read = len(d.entries)
		return remaining, nil
	}

	if len(remaining) == 0 {
		return nil, io.EOF
	}

	if n > len(remaining) {
		n = len(remaining)
	}
	d.read += n
	return remaining[:n], nil
}
