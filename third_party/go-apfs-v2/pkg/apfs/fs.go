// io/fs adapter: Volume implements fs.FS, fs.ReadDirFS, fs.StatFS and
// fs.ReadFileFS, so volumes can be walked with fs.WalkDir, tested with
// testing/fstest and passed to anything that consumes an fs.FS.
//
// Symlinks are never followed: Stat and Open return the link itself, like
// archive-backed file systems. Use Readlink to resolve targets.
package apfs

import (
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/unixmode"
)

var (
	_ fs.FS         = (*Volume)(nil)
	_ fs.ReadDirFS  = (*Volume)(nil)
	_ fs.StatFS     = (*Volume)(nil)
	_ fs.ReadFileFS = (*Volume)(nil)
)

// entryByFSName resolves an fs.FS path ("." or "a/b/c") to a file entry.
func (v *Volume) entryByFSName(op, name string) (*FileEntry, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: op, Path: name, Err: fs.ErrInvalid}
	}

	apfsPath := "/"
	if name != "." {
		apfsPath = "/" + name
	}

	entry, err := v.FileEntryByPath(apfsPath)
	if err != nil {
		return nil, &fs.PathError{Op: op, Path: name, Err: fmt.Errorf("%w: %v", fs.ErrNotExist, err)}
	}

	return entry, nil
}

// Open implements fs.FS.
func (v *Volume) Open(name string) (fs.File, error) {
	entry, err := v.entryByFSName("open", name)
	if err != nil {
		return nil, err
	}

	info, err := newFileInfo(path.Base(name), entry)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}

	if info.IsDir() {
		return &apfsDir{volume: v, name: name, info: info}, nil
	}

	return &apfsFile{entry: entry, info: info}, nil
}

// ReadDir implements fs.ReadDirFS. Entries are sorted by filename as the
// interface requires.
func (v *Volume) ReadDir(name string) ([]fs.DirEntry, error) {
	entry, err := v.entryByFSName("readdir", name)
	if err != nil {
		return nil, err
	}

	entries, err := readDirEntries(entry)
	if err != nil {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: err}
	}

	return entries, nil
}

// Stat implements fs.StatFS. Symlinks are not followed.
func (v *Volume) Stat(name string) (fs.FileInfo, error) {
	entry, err := v.entryByFSName("stat", name)
	if err != nil {
		return nil, err
	}

	info, err := newFileInfo(path.Base(name), entry)
	if err != nil {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: err}
	}

	return info, nil
}

// ReadFile implements fs.ReadFileFS.
func (v *Volume) ReadFile(name string) ([]byte, error) {
	entry, err := v.entryByFSName("readfile", name)
	if err != nil {
		return nil, err
	}

	size, err := entry.Size()
	if err != nil {
		return nil, &fs.PathError{Op: "readfile", Path: name, Err: err}
	}

	if size == 0 {
		return []byte{}, nil
	}

	data := make([]byte, size)
	n, err := entry.ReadAt(data, 0)
	if err != nil && err != io.EOF {
		return nil, &fs.PathError{Op: "readfile", Path: name, Err: err}
	}

	return data[:n], nil
}

// Readlink returns the target of the symbolic link at name.
func (v *Volume) Readlink(name string) (string, error) {
	entry, err := v.entryByFSName("readlink", name)
	if err != nil {
		return "", err
	}

	target, err := entry.SymbolicLinkTarget()
	if err != nil {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: err}
	}

	return target, nil
}

// Xattrs returns the extended attributes of the file at name.
func (v *Volume) Xattrs(name string) (map[string][]byte, error) {
	entry, err := v.entryByFSName("xattrs", name)
	if err != nil {
		return nil, err
	}

	count, err := entry.NumberOfExtendedAttributes()
	if err != nil {
		return nil, &fs.PathError{Op: "xattrs", Path: name, Err: err}
	}

	attrs := make(map[string][]byte, count)
	for index := range count {
		attr, err := entry.ExtendedAttributeByIndex(index)
		if err != nil {
			return nil, &fs.PathError{Op: "xattrs", Path: name, Err: err}
		}

		attrName, err := attr.UTF8Name()
		if err != nil {
			continue
		}

		data, err := readAllFromReaderAt(attr)
		if err != nil {
			return nil, &fs.PathError{Op: "xattrs", Path: name, Err: fmt.Errorf("attribute %s: %w", attrName, err)}
		}
		attrs[attrName] = data
	}

	return attrs, nil
}

func readAllFromReaderAt(attr *ExtendedAttribute) ([]byte, error) {
	if _, err := attr.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(readerFromXattr{attr})
}

// readerFromXattr adapts ExtendedAttribute's Read method to io.Reader
type readerFromXattr struct {
	attr *ExtendedAttribute
}

func (r readerFromXattr) Read(p []byte) (int, error) {
	return r.attr.Read(p)
}

// fileInfo implements fs.FileInfo for APFS entries. Sys returns the *Inode.
type fileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	inode   *Inode
}

func newFileInfo(name string, entry *FileEntry) (*fileInfo, error) {
	if entry.Inode == nil {
		return nil, fmt.Errorf("file entry has no inode")
	}

	inode := entry.Inode

	mode := unixmode.FilePermissions(inode.FileMode)
	switch inode.FileMode & 0xF000 {
	case 0x4000: // S_IFDIR
		mode |= fs.ModeDir
	case 0xA000: // S_IFLNK
		mode |= fs.ModeSymlink
	case 0x2000: // S_IFCHR
		mode |= fs.ModeDevice | fs.ModeCharDevice
	case 0x6000: // S_IFBLK
		mode |= fs.ModeDevice
	case 0x1000: // S_IFIFO
		mode |= fs.ModeNamedPipe
	case 0xC000: // S_IFSOCK
		mode |= fs.ModeSocket
	}

	size := int64(0)
	if mode&fs.ModeDir == 0 {
		fileSize, err := entry.Size()
		if err == nil {
			size = int64(fileSize)
		}
	}

	return &fileInfo{
		name:    name,
		size:    size,
		mode:    mode,
		modTime: time.Unix(0, int64(inode.ModificationTime)),
		inode:   inode,
	}, nil
}

func (fi *fileInfo) Name() string       { return fi.name }
func (fi *fileInfo) Size() int64        { return fi.size }
func (fi *fileInfo) Mode() fs.FileMode  { return fi.mode }
func (fi *fileInfo) ModTime() time.Time { return fi.modTime }
func (fi *fileInfo) IsDir() bool        { return fi.mode.IsDir() }
func (fi *fileInfo) Sys() any           { return fi.inode }

// dirEntry implements fs.DirEntry.
type dirEntry struct {
	info *fileInfo
}

func (de dirEntry) Name() string               { return de.info.name }
func (de dirEntry) IsDir() bool                { return de.info.IsDir() }
func (de dirEntry) Type() fs.FileMode          { return de.info.mode.Type() }
func (de dirEntry) Info() (fs.FileInfo, error) { return de.info, nil }

func readDirEntries(dir *FileEntry) ([]fs.DirEntry, error) {
	count, err := dir.NumberOfSubFileEntries()
	if err != nil {
		return nil, err
	}

	entries := make([]fs.DirEntry, 0, count)
	for index := range count {
		child, err := dir.SubFileEntryByIndex(index)
		if err != nil {
			return nil, fmt.Errorf("unable to read directory entry %d: %w", index, err)
		}

		childName, err := child.UTF8Name()
		if err != nil {
			return nil, fmt.Errorf("unable to get name of directory entry %d: %w", index, err)
		}

		info, err := newFileInfo(childName, child)
		if err != nil {
			return nil, fmt.Errorf("unable to stat directory entry %s: %w", childName, err)
		}

		entries = append(entries, dirEntry{info: info})
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	return entries, nil
}

// apfsFile implements fs.File, io.ReaderAt and io.Seeker for regular files
// and symlinks.
type apfsFile struct {
	entry  *FileEntry
	info   *fileInfo
	offset int64
}

func (f *apfsFile) Stat() (fs.FileInfo, error) { return f.info, nil }

func (f *apfsFile) Read(p []byte) (int, error) {
	n, err := f.ReadAt(p, f.offset)
	f.offset += int64(n)
	return n, err
}

func (f *apfsFile) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if off >= f.info.size {
		return 0, io.EOF
	}

	// FileEntry.ReadAt reads whole blocks and would pad past end-of-file;
	// clamp the request to the remaining bytes ourselves
	remaining := f.info.size - off
	clamped := p
	if int64(len(p)) > remaining {
		clamped = p[:remaining]
	}

	n, err := f.entry.ReadAt(clamped, off)
	if err != nil && err != io.EOF {
		return n, err
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (f *apfsFile) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		offset += f.offset
	case io.SeekEnd:
		offset += f.info.size
	default:
		return 0, fmt.Errorf("invalid whence: %d", whence)
	}
	if offset < 0 {
		return 0, fmt.Errorf("negative seek offset")
	}
	f.offset = offset
	return offset, nil
}

func (f *apfsFile) Close() error { return nil }

// apfsDir implements fs.ReadDirFile for directories.
type apfsDir struct {
	volume  *Volume
	name    string
	info    *fileInfo
	entries []fs.DirEntry
	read    int
}

func (d *apfsDir) Stat() (fs.FileInfo, error) { return d.info, nil }

func (d *apfsDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.name, Err: fmt.Errorf("is a directory")}
}

func (d *apfsDir) Close() error { return nil }

func (d *apfsDir) ReadDir(n int) ([]fs.DirEntry, error) {
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
