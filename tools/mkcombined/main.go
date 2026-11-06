package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// fileValue streams a source file's bytes into the writer without
// materializing it in memory.
type fileValue struct {
	r    io.ReaderAt
	size int64
}

func (v *fileValue) ReadAt(p []byte, off int64) (int, error) { return v.r.ReadAt(p, off) }
func (v *fileValue) Size() int64                             { return v.size }

func stamp(ns uint64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, int64(ns))
}

type walker struct {
	vol   *apfs.Volume
	count int
	skip  map[string]int
	// skipPath omits whole subtrees, keyed by image-relative path.  It lets
	// the cryptex overlay leave System/Library/dyld alone: those caches are
	// already installed from the (identical) cryptex onto the system volume,
	// and duplicating the multi-gigabyte cache inside Preboot buys nothing.
	skipPath map[string]bool
	// flatten writes every hard-linked name as its own independent file
	// instead of reproducing the APFS sibling-link records. Bring-up images
	// use it because the guest's APFS client is sensitive to how a synthetic
	// writer lays out siblings, and hard-linked launchd property lists (e.g.
	// com.apple.powerd.plist, which is also inside powerd.bundle) fail lookup
	// with ENOENT when they are written that way. The cost is one copy of the
	// file per extra name.
	flatten bool
}

func (w *walker) children(dir string) ([]*apfswrite.Entry, error) {
	des, err := w.vol.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]*apfswrite.Entry, 0, len(des))
	for _, de := range des {
		name := de.Name()
		full := name
		if dir != "." {
			full = dir + "/" + name
		}
		if w.skipPath[full] {
			w.skip["skip:"+full]++
			continue
		}
		info, err := de.Info()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", full, err)
		}
		inode, _ := info.Sys().(*apfs.Inode)
		if inode == nil {
			return nil, fmt.Errorf("%s: no inode", full)
		}
		mode := info.Mode()
		flags := inode.BSDFlags
		e := &apfswrite.Entry{
			Name:         name,
			Mode:         mode,
			ModeExplicit: true,
			Times: &hostdata.FileTimes{
				Birth:  stamp(inode.CreationTime),
				Modify: stamp(inode.ModificationTime),
				Change: stamp(inode.InodeChangeTime),
				Access: stamp(inode.AccessTime),
			},
			BSDFlags: &flags,
			UID:      inode.OwnerIdentifier,
			GID:      inode.GroupIdentifier,
		}

		vals, xerr := w.vol.XattrValues(full)
		if xerr == nil && len(vals) > 0 {
			// The writer emits the symlink target itself.
			delete(vals, "com.apple.fs.symlink")
			if len(vals) > 0 {
				e.XattrValues = vals
			}
		}

		switch {
		case mode&os.ModeSymlink != 0:
			target, err := w.vol.Readlink(full)
			if err != nil {
				return nil, fmt.Errorf("%s: readlink: %w", full, err)
			}
			e.Data = []byte(target)
		case mode.IsDir():
			kids, err := w.children(full)
			if err != nil {
				return nil, err
			}
			e.Children = kids
		case mode.IsRegular():
			if _, compressed := vals["com.apple.decmpfs"]; compressed {
				// Keep the decmpfs form: no data fork, attribute carried above.
			} else if info.Size() > 0 {
				f, err := w.vol.Open(full)
				if err != nil {
					return nil, fmt.Errorf("%s: open: %w", full, err)
				}
				ra, ok := f.(io.ReaderAt)
				if !ok {
					return nil, fmt.Errorf("%s: file is not a ReaderAt", full)
				}
				e.DataValue = &fileValue{r: ra, size: info.Size()}
			}
			if inode.NumberOfLinks > 1 && !w.flatten {
				e.LinkGroup = inode.Identifier
			}
		default:
			w.skip[mode.Type().String()]++
			continue
		}

		w.count++
		if w.count%25000 == 0 {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			fmt.Fprintf(os.Stderr, "  %d entries heap=%.0fMB sys=%.0fMB\n", w.count,
				float64(ms.HeapAlloc)/(1<<20), float64(ms.Sys)/(1<<20))
		}
		out = append(out, e)
	}
	return out, nil
}

func dirEntry(name string, kids ...*apfswrite.Entry) *apfswrite.Entry {
	return &apfswrite.Entry{Name: name, Mode: os.ModeDir | 0755, ModeExplicit: true, UID: 0, GID: 0, Children: kids}
}

// ensureDir walks (and creates as needed) the slash-separated directory path
// under root, returning the directory entry.
func ensureDir(root *apfswrite.Entry, parts ...string) *apfswrite.Entry {
	cur := root
	for _, name := range parts {
		var next *apfswrite.Entry
		for _, e := range cur.Children {
			if e.Name == name && e.Mode.IsDir() {
				next = e
				break
			}
		}
		if next == nil {
			next = dirEntry(name)
			cur.Children = append(cur.Children, next)
		}
		cur = next
	}
	return cur
}

// dataRoot builds the Data volume's root.  A real install populates that
// volume from the installer's template, /System/Library/Templates/Data, and
// daemons assume the template's directories exist: /Library/Preferences (logd
// creates /Library/Preferences/Logging and its sandbox profile allows only
// that subpath, so a missing parent makes the mkdir fail with EPERM and logd
// traps), /private/etc (tzinit links localtime into it), the local directory
// service nodes opendirectoryd needs, and so on.  Use the template when the
// source volume has one and only add the directories the system creates on
// first boot on top of it.
func dataRoot(w *walker) *apfswrite.Entry {
	root := &apfswrite.Entry{}
	const tmpl = "System/Library/Templates/Data"
	if kids, err := w.children(tmpl); err == nil {
		root.Children = kids
		fmt.Fprintf(os.Stderr, "Data volume root from %s (%d entries)\n", tmpl, len(kids))
	} else {
		root = dataSkeleton()
		fmt.Fprintf(os.Stderr, "no %s (%v); using the minimal Data skeleton\n", tmpl, err)
	}
	ensureDir(root, "private", "var", "db", "diagnostics")
	ensureDir(root, "private", "var", "db", "diagnostics", "timesync")
	ensureDir(root, "private", "var", "db", "uuidtext")
	ensureDir(root, "private", "var", "db", "timezone")
	ensureDir(root, "private", "etc")
	return root
}

func dataSkeleton() *apfswrite.Entry {
	return &apfswrite.Entry{Children: []*apfswrite.Entry{
		dirEntry("private",
			dirEntry("var",
				// tzinit runs as an early boot task and cannot start without a
				// writable /var/db/timezone: it links the zone data from the
				// System volume (/usr/share/zoneinfo.default) into it.  With
				// the directory missing the symlink fails with ENOENT, tzinit
				// exits 2, and launchd panics the machine.
				//
				// Diagnostics and uuidtext are the same kind of install-time
				// state: logd opens them with O_DIRECTORY and its libtrace
				// store traps (SIGTRAP) when the open fails, which launchd
				// treats as a critical crash and panics on.  Both live on the
				// Data volume on a real install, not on the System volume.
				dirEntry("db",
					dirEntry("timezone"),
					dirEntry("diagnostics", dirEntry("timesync")),
					dirEntry("uuidtext"),
				), dirEntry("log"), dirEntry("run"), dirEntry("tmp"),
				dirEntry("root"), dirEntry("folders"), dirEntry("vm"), dirEntry("audit"),
			),
			dirEntry("tmp"),
		),
		dirEntry("usr",
			dirEntry("local"),
			dirEntry("libexec", dirEntry("cups")),
			dirEntry("share", dirEntry("snmp")),
		),
		dirEntry("System", dirEntry("Library",
			dirEntry("PreinstalledAssets"),
			dirEntry("AssetsV2"),
			dirEntry("PreinstalledAssetsV2"),
			dirEntry("Speech"),
			dirEntry("CoreServices", dirEntry("CoreTypes.bundle", dirEntry("Contents", dirEntry("Library")))),
		)),
		dirEntry("Library"),
		dirEntry("Applications"),
		dirEntry("Users"),
		dirEntry("Volumes"),
		dirEntry("cores"),
		dirEntry("opt"),
		dirEntry("pkg"),
	}}
}

// hostTree turns a host directory into writer entries, streaming file
// contents.  It exists for payloads that are not part of the source image,
// such as the dyld shared cache that macOS 27 keeps in the SystemOS cryptex.
func hostTree(dir string) ([]*apfswrite.Entry, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]*apfswrite.Entry, 0, len(des))
	for _, de := range des {
		p := filepath.Join(dir, de.Name())
		info, err := de.Info()
		if err != nil {
			return nil, err
		}
		mode := info.Mode().Perm()
		if de.IsDir() {
			kids, err := hostTree(p)
			if err != nil {
				return nil, err
			}
			out = append(out, &apfswrite.Entry{
				Name: de.Name(), Mode: os.ModeDir | mode, ModeExplicit: true,
				UID: 0, GID: 0, Children: kids,
			})
			continue
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s: unsupported file type %v", p, info.Mode().Type())
		}
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		// The dyld shared cache on a sealed volume carries SF_RESTRICTED;
		// the kernel's shared-region mapping path refuses a cache that is
		// neither in the trust cache nor flagged SIP-protected
		// (bsd/vm/vm_unix.c, vm_shared_region_map_file_np).
		flags := uint32(0x00080000) // SF_RESTRICTED
		out = append(out, &apfswrite.Entry{
			Name: de.Name(), Mode: mode, ModeExplicit: true,
			UID: 0, GID: 0, BSDFlags: &flags,
			DataValue: &fileValue{r: f, size: info.Size()},
		})
	}
	return out, nil
}

// installPath walks to the parent of the slash-separated path under the
// System volume root, creating directories as needed, and replaces any entry
// named by the last component with `leaf`.
func installPath(root *apfswrite.Entry, path string, leaf *apfswrite.Entry) {
	parts := strings.Split(path, "/")
	cur := root
	for _, name := range parts[:len(parts)-1] {
		var next *apfswrite.Entry
		for _, e := range cur.Children {
			if e.Name == name && e.Mode.IsDir() {
				next = e
				break
			}
		}
		if next == nil {
			next = dirEntry(name)
			cur.Children = append(cur.Children, next)
		}
		cur = next
	}
	kept := cur.Children[:0]
	for _, e := range cur.Children {
		if e.Name != leaf.Name {
			kept = append(kept, e)
		}
	}
	cur.Children = append(kept, leaf)
}

// installHostDir places a host directory at the slash-separated path under the
// System volume root, replacing any existing entry of that name.
func installHostDir(root *apfswrite.Entry, path, dir string) error {
	kids, err := hostTree(dir)
	if err != nil {
		return err
	}
	parts := strings.Split(path, "/")
	installPath(root, path, dirEntry(parts[len(parts)-1], kids...))
	return nil
}

// installHostFile replaces one file under the System volume root with a host
// file.  It exists for bring-up instrumentation: a launchd job's property list
// (e.g. com.apple.logd.plist with StandardErrorPath), or a binary built here
// rather than shipped on the volume.  The replacement keeps the mode of the
// file it replaces when there is one, so a patched daemon stays executable.
func installHostFile(root *apfswrite.Entry, path, src string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	parts := strings.Split(path, "/")
	name := parts[len(parts)-1]
	mode := os.FileMode(0644)
	var uid, gid uint32
	// Reuse the replaced entry's ownership and permissions.
	if cur := findEntry(root, path); cur != nil {
		mode = cur.Mode.Perm()
		if cur.Mode&0111 != 0 {
			mode |= 0111
		}
		uid, gid = cur.UID, cur.GID
	}
	e := &apfswrite.Entry{
		Name: name, Mode: mode, ModeExplicit: true, UID: uid, GID: gid,
		DataValue: &fileValue{r: f, size: info.Size()},
	}
	installPath(root, path, e)
	return nil
}

// installHostDecmpfs installs a file in the exact form the sealed SystemOS
// cryptex stores it: a com.apple.decmpfs header attribute plus the compressed
// bytes in com.apple.ResourceFork, with an empty data fork.  Nothing is
// decompressed here.  macOS decodes the file when it is read, which is also how
// every compressed file copied from the root DMG works, so a cryptex-only file
// whose payload a host tool cannot decode can still be transplanted verbatim.
func installHostDecmpfs(root *apfswrite.Entry, path, xattrSrc, forkSrc string) error {
	xattr, err := os.ReadFile(xattrSrc)
	if err != nil {
		return err
	}
	fork, err := os.ReadFile(forkSrc)
	if err != nil {
		return err
	}
	parts := strings.Split(path, "/")
	mode := os.FileMode(0755)
	var uid, gid uint32
	if cur := findEntry(root, path); cur != nil {
		mode = cur.Mode.Perm()
		uid, gid = cur.UID, cur.GID
	}
	e := &apfswrite.Entry{
		Name: parts[len(parts)-1], Mode: mode, ModeExplicit: true, UID: uid, GID: gid,
		Xattrs: map[string][]byte{
			"com.apple.decmpfs":      xattr,
			"com.apple.ResourceFork": fork,
		},
	}
	installPath(root, path, e)
	return nil
}

// findEntry returns the entry at path under root, or nil.
func findEntry(root *apfswrite.Entry, path string) *apfswrite.Entry {
	cur := root
	for _, name := range strings.Split(path, "/") {
		var next *apfswrite.Entry
		for _, e := range cur.Children {
			if e.Name == name {
				next = e
				break
			}
		}
		if next == nil {
			return nil
		}
		cur = next
	}
	return cur
}

// overlayTree merges src into dst, the way a grafted cryptex overlays the
// sealed system volume: a cryptex entry replaces the base entry of the same
// name, except that two directories merge recursively so files that only exist
// in the base system survive.  It returns the merged slice.
func overlayTree(dst, src []*apfswrite.Entry) []*apfswrite.Entry {
	for _, se := range src {
		idx := -1
		for i, de := range dst {
			if de.Name == se.Name {
				idx = i
				break
			}
		}
		if idx < 0 {
			dst = append(dst, se)
			continue
		}
		if dst[idx].Mode.IsDir() && se.Mode.IsDir() {
			dst[idx].Children = overlayTree(dst[idx].Children, se.Children)
			continue
		}
		dst[idx] = se
	}
	return dst
}

func uuidString(u [16]byte) string {
	s := fmt.Sprintf("%x", u)
	return strings.ToUpper(s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32])
}

// growTo extends f to size by appending from EOF. NTFS3 refuses to extend a
// file across a hole, which is what a truncate or a far write would do.
func growTo(f *os.File, size int64) error {
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() >= size {
		return nil
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	zero := make([]byte, 1<<20)
	for cur := st.Size(); cur < size; {
		n := int64(len(zero))
		if size-cur < n {
			n = size - cur
		}
		if _, err := f.Write(zero[:n]); err != nil {
			return err
		}
		cur += n
	}
	return f.Sync()
}

// ---------------------------------------------------------------------------
// GPT.
//
// A restored Apple Silicon disk is one GPT disk: the iSC container is a
// partition of it (type 69646961-6700-11AA-AA11-00306543ECAC), not a separate
// device, and its "Content Hint" in IOKit is exactly that type GUID.
// ---------------------------------------------------------------------------

const (
	gptLBASize   = 512
	gptPartStart = 1 << 20 // 1 MiB, the usual GPT alignment
	gptEntries   = 128
	gptEntrySize = 128
)

// offsetWriter places the APFS container at a partition offset.
type offsetWriter struct {
	f   *os.File
	off int64
}

func (w *offsetWriter) WriteAt(p []byte, off int64) (int, error) {
	return w.f.WriteAt(p, off+w.off)
}

// guidBytes encodes a GUID string the way GPT stores one: the first three
// fields little-endian, the last two as-is.
func guidBytes(s string) ([16]byte, error) {
	var g [16]byte
	parts := strings.Split(s, "-")
	if len(parts) != 5 ||
		len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 ||
		len(parts[3]) != 4 || len(parts[4]) != 12 {
		return g, fmt.Errorf("bad GUID %q", s)
	}
	var raw [16]byte
	n := 0
	for _, p := range parts {
		for i := 0; i < len(p); i += 2 {
			var b byte
			if _, err := fmt.Sscanf(p[i:i+2], "%02x", &b); err != nil {
				return g, fmt.Errorf("bad GUID %q: %w", s, err)
			}
			raw[n] = b
			n++
		}
	}
	g[0], g[1], g[2], g[3] = raw[3], raw[2], raw[1], raw[0]
	g[4], g[5] = raw[5], raw[4]
	g[6], g[7] = raw[7], raw[6]
	copy(g[8:], raw[8:])
	return g, nil
}

// putGuid stores a GUID the way GPT does.  guidBytes already produced the
// on-disk byte order (EFI GUID: Data1/2/3 little-endian), so this is a plain
// copy; swapping here again would store the type GUID in the wrong order and
// the partition's IOKit "Content Hint" would name a partition type no driver
// matches.
func putGuid(dst []byte, g [16]byte) {
	copy(dst[:16], g[:])
}

type gptPart struct {
	typ        string
	unique     string
	name       string
	first, end uint64
}

// writeGPT writes the protective MBR, the primary GPT, and the backup GPT at
// the end of the file's final size.
func writeGPT(f *os.File, totalLBAs uint64, parts []gptPart) error {
	mbr := make([]byte, gptLBASize)
	mbr[450] = 0xee
	mbr[451], mbr[452], mbr[453] = 0xff, 0xff, 0xff
	binary.LittleEndian.PutUint32(mbr[454:], 1)
	size := totalLBAs - 1
	if size > 0xffffffff {
		size = 0xffffffff
	}
	binary.LittleEndian.PutUint32(mbr[458:], uint32(size))
	mbr[510], mbr[511] = 0x55, 0xaa
	if _, err := f.WriteAt(mbr, 0); err != nil {
		return err
	}

	entries, err := gptEntryBytes(parts)
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(entries, 2*gptLBASize); err != nil {
		return err
	}

	hdr, err := gptHeaderBytes(totalLBAs, 1, totalLBAs-1, 2, entries)
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(hdr, gptLBASize); err != nil {
		return err
	}
	return nil
}

func gptEntryBytes(parts []gptPart) ([]byte, error) {
	entries := make([]byte, gptEntries*gptEntrySize)
	for i, p := range parts {
		e := entries[i*gptEntrySize:]
		t, err := guidBytes(p.typ)
		if err != nil {
			return nil, err
		}
		u, err := guidBytes(p.unique)
		if err != nil {
			return nil, err
		}
		putGuid(e[0:16], t)
		putGuid(e[16:32], u)
		binary.LittleEndian.PutUint64(e[32:], p.first)
		binary.LittleEndian.PutUint64(e[40:], p.end)
		for j := 0; j < len(p.name) && j < 36; j++ {
			e[56+j*2] = p.name[j]
		}
	}
	return entries, nil
}

// gptHeaderBytes builds one GPT header with the given current/backup LBA and
// entry-array position.
func gptHeaderBytes(totalLBAs, current, backup, entriesLBA uint64, entries []byte) ([]byte, error) {
	disk, err := guidBytes("49534300-0000-4000-8000-0000000000d0")
	if err != nil {
		return nil, err
	}
	hdr := make([]byte, 92)
	copy(hdr[0:], "EFI PART")
	binary.LittleEndian.PutUint32(hdr[8:], 0x00010000)
	binary.LittleEndian.PutUint32(hdr[12:], 92)
	binary.LittleEndian.PutUint64(hdr[24:], current)
	binary.LittleEndian.PutUint64(hdr[32:], backup)
	binary.LittleEndian.PutUint64(hdr[40:], 34)
	binary.LittleEndian.PutUint64(hdr[48:], totalLBAs-34)
	putGuid(hdr[56:72], disk)
	binary.LittleEndian.PutUint64(hdr[72:], entriesLBA)
	binary.LittleEndian.PutUint32(hdr[80:], gptEntries)
	binary.LittleEndian.PutUint32(hdr[84:], gptEntrySize)
	binary.LittleEndian.PutUint32(hdr[88:], crc32.ChecksumIEEE(entries))
	binary.LittleEndian.PutUint32(hdr[16:], crc32.ChecksumIEEE(hdr))
	return hdr, nil
}

// writeGPTBackup writes the backup entries and header.  It has to run after
// the image has been grown: NTFS3 refuses a write past the end of the file, so
// the far end cannot be populated while the container is still being written.
func writeGPTBackup(f *os.File, totalLBAs uint64, parts []gptPart) error {
	entries, err := gptEntryBytes(parts)
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(entries, int64((totalLBAs-33)*gptLBASize)); err != nil {
		return err
	}
	hdr, err := gptHeaderBytes(totalLBAs, totalLBAs-1, 1, totalLBAs-33, entries)
	if err != nil {
		return err
	}
	_, err = f.WriteAt(hdr, int64((totalLBAs-1)*gptLBASize))
	return err
}

// copyAt copies a whole file to dst at off.
func copyAt(dst *os.File, off int64, path string) error {
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()
	buf := make([]byte, 1<<20)
	for cur := int64(0); ; {
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := dst.WriteAt(buf[:n], off+cur); werr != nil {
				return werr
			}
			cur += int64(n)
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

// multiFlag collects a repeatable -flag value.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func main() {
	src := flag.String("src", "", "source APFS image")
	out := flag.String("out", "", "output container image")
	size := flag.Int64("size", 0, "container size in bytes")
	subtree := flag.String("subtree", ".", "subtree to copy (as the new volume root)")
	noExtra := flag.Bool("noextra", false, "omit Data/Preboot volumes (fidelity testing)")
	dyldDir := flag.String("dyld", "", "host directory to install at System/Library/dyld")
	var injects multiFlag
	flag.Var(&injects, "inject", "hostfile:dstpath under the System volume root, repeatable")
	var prebootFiles multiFlag
	flag.Var(&prebootFiles, "preboot-file", "hostfile:path under the Preboot per-install directory, repeatable")
	var cryptexes multiFlag
	flag.Var(&cryptexes, "cryptex", "cryptex APFS image whose volume-root tree is overlaid onto the System volume, repeatable")
	var cryptexSkip multiFlag
	flag.Var(&cryptexSkip, "cryptex-skip", "image-relative path to omit while overlaying cryptexes, repeatable")
	var decmpfsInjects multiFlag
	flag.Var(&decmpfsInjects, "inject-decmpfs", "xattrfile|forkfile|dstpath: install a decmpfs-compressed file verbatim, repeatable")
	iscPath := flag.String("isc", "", "iSC container (tools/mkisc -container) to place before the main container in a GPT disk")
	dry := flag.Bool("dry", false, "walk only")
	flatten := flag.Bool("flathardlinks", false, "write hard-linked names as independent files instead of APFS sibling links")
	flag.Parse()

	container, closer, err := apfs.OpenImage(*src, nil)
	must(err)
	defer closer.Close()

	vol, err := container.VolumeBySelector("0")
	must(err)

	volUUID, err := vol.Identifier()
	must(err)
	group := [16]byte{0x7a, 0x1c, 0x9e, 0x42, 0x3b, 0x5d, 0x4f, 0x60, 0x9d, 0x2e, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}

	t0 := time.Now()
	elapsed := func(what string) {
		fmt.Fprintf(os.Stderr, "[%s] %s\n", time.Since(t0).Round(time.Second), what)
	}

	w := &walker{vol: vol, skip: map[string]int{}, flatten: *flatten}
	kids, err := w.children(*subtree)
	must(err)
	elapsed(fmt.Sprintf("walked base volume: %d entries", w.count))
	root := &apfswrite.Entry{Children: kids}
	// A grafted cryptex is a union overlay of its volume root onto the
	// system volume.  Reconstruct that here instead of depending on the
	// in-guest graft, which needs the sealed Preboot/IGC layout our
	// synthetic container does not have.  Files present in both trees come
	// from the cryptex; directories merge so base-only files survive.
	var cryptexClosers []io.Closer
	for _, img := range cryptexes {
		cc, ccloser, err := apfs.OpenImage(img, nil)
		must(err)
		cryptexClosers = append(cryptexClosers, ccloser)
		cv, err := cc.VolumeBySelector("0")
		must(err)
		cw := &walker{vol: cv, skip: map[string]int{}, skipPath: map[string]bool{}, flatten: *flatten}
		for _, p := range cryptexSkip {
			cw.skipPath[p] = true
		}
		ckids, err := cw.children(".")
		must(err)
		root.Children = overlayTree(root.Children, ckids)
		fmt.Fprintf(os.Stderr, "overlaid cryptex %s: %d entries (skipped: %v)\n",
			img, cw.count, cw.skip)
		elapsed(fmt.Sprintf("overlaid cryptex %s", filepath.Base(img)))
	}
	defer func() {
		for _, c := range cryptexClosers {
			c.Close()
		}
	}()
	if *dyldDir != "" {
		// macOS 27 no longer ships the dyld shared cache on the System
		// volume: it lives in the Cryptex1,SystemOS cryptex, which needs
		// the full cryptex graft to mount.  Installing the caches here
		// lets the level-1 dylib_cache stage find them on the system
		// volume instead.
		must(installHostDir(root, "System/Library/dyld", *dyldDir))
		fmt.Fprintf(os.Stderr, "installed %s at System/Library/dyld\n", *dyldDir)
	}
	for _, spec := range injects {
		src, dst, ok := strings.Cut(spec, ":")
		if !ok || src == "" || dst == "" {
			fmt.Fprintf(os.Stderr, "bad -inject %q: want hostfile:dstpath\n", spec)
			os.Exit(2)
		}
		must(installHostFile(root, dst, src))
		fmt.Fprintf(os.Stderr, "injected %s at %s\n", src, dst)
	}
	for _, spec := range decmpfsInjects {
		parts := strings.Split(spec, "|")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			fmt.Fprintf(os.Stderr, "bad -inject-decmpfs %q: want xattrfile|forkfile|dstpath\n", spec)
			os.Exit(2)
		}
		must(installHostDecmpfs(root, parts[2], parts[0], parts[1]))
		fmt.Fprintf(os.Stderr, "injected decmpfs %s + %s at %s\n", parts[0], parts[1], parts[2])
	}
	// Preboot cryptex1/current holds the graftable os.dmg/app.dmg images
	// together with their IMG4 root-hash seals and trust caches.  libignition
	// opens cryptex1/current during early boot and grafts what it finds there;
	// an empty directory is why the VM so far booted with /System/Cryptexes
	// dangling and a system volume that is missing the cryptex overlay.
	prebootRoot := &apfswrite.Entry{Children: []*apfswrite.Entry{
		dirEntry("boot"), dirEntry("cryptex1", dirEntry("current")), dirEntry("restore"),
	}}
	for _, spec := range prebootFiles {
		src, dst, ok := strings.Cut(spec, ":")
		if !ok || src == "" || dst == "" {
			fmt.Fprintf(os.Stderr, "bad -preboot-file %q: want hostfile:dstpath\n", spec)
			os.Exit(2)
		}
		must(installHostFile(prebootRoot, dst, src))
		fmt.Fprintf(os.Stderr, "installed preboot file %s at %s\n", src, dst)
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	fmt.Fprintf(os.Stderr, "source entries: %d (skipped: %v) heap=%.0fMB sys=%.0fMB\n",
		w.count, w.skip, float64(ms.HeapAlloc)/(1<<20), float64(ms.Sys)/(1<<20))
	if *dry {
		return
	}

	specs := []apfswrite.VolumeSpec{}
	if *noExtra {
		specs = append(specs, apfswrite.VolumeSpec{
			Name: "Macintosh HD", UUID: volUUID, Role: apfs.VolumeRoleSystem, Root: root,
		})
	} else {
		specs = append(specs,
			apfswrite.VolumeSpec{Name: "Macintosh HD", UUID: volUUID, Role: apfs.VolumeRoleSystem, VolumeGroupID: group, Root: root},
			apfswrite.VolumeSpec{Name: "Macintosh HD - Data", Role: apfs.VolumeRoleData, VolumeGroupID: group, Root: dataRoot(w)},
			// The per-install directory under /System/Volumes/Preboot is
			// named by the value iBoot puts in /chosen/boot-uuid, which is
			// what libignition uses as the "volume group uuid": it opens
			// "<preboot mount>/<kern.bootuuid>".  This container carries no
			// on-disk volume-group record (our writer has no support for
			// one), so the kernel falls back to matching boot-uuid against
			// the boot *volume* UUID and reports that as the group UUID.
			// Name the directory accordingly.
			apfswrite.VolumeSpec{Name: "Preboot", Role: apfs.VolumeRolePreboot, Root: &apfswrite.Entry{Children: []*apfswrite.Entry{
				dirEntry(uuidString(volUUID), prebootRoot.Children...),
				// The system volume's /System/Cryptexes/{OS,App,Rosetta,
				// ExclaveOS} entries are com.apple.fs.symlink links whose
				// primary target is ../../System/Volumes/Preboot/Cryptexes/*
				// and whose altlink is .../Cryptexes/Incoming/OS.  libignition
				// opens the canonical root /System/Volumes/Preboot/Cryptexes/OS/
				// during the cryptex1 graft; the Preboot volume must actually
				// contain those directories or the graft aborts with ENOENT.
				dirEntry("Cryptexes",
					dirEntry("OS"),
					dirEntry("App"),
					dirEntry("Rosetta"),
					dirEntry("ExclaveOS"),
					dirEntry("Incoming", dirEntry("OS")),
				),
			}}},
		)
	}

	f, err := os.Create(*out)
	must(err)
	defer f.Close()

	var (
		cw        io.WriterAt = f
		offset    int64
		totalLen  int64 = *size
		totalLBAs uint64
		parts     []gptPart
	)
	if *iscPath != "" {
		st, err := os.Stat(*iscPath)
		must(err)
		if st.Size()%gptLBASize != 0 || st.Size()%gptPartStart != 0 {
			must(fmt.Errorf("iSC container size %d is not a multiple of 1 MiB", st.Size()))
		}
		offset = int64(gptPartStart) + st.Size()
		mainLBAs := uint64(*size) / gptLBASize
		mainFirst := uint64(offset) / gptLBASize
		total := offset + *size + gptPartStart
		totalLBAs = uint64((total + gptLBASize - 1) / gptLBASize)
		if totalLBAs%2048 != 0 {
			totalLBAs += 2048 - totalLBAs%2048
		}
		totalLen = int64(totalLBAs) * gptLBASize
		parts = []gptPart{
			{
				typ:    "69646961-6700-11AA-AA11-00306543ECAC",
				unique: "49534300-0000-4000-8000-0000000000e1",
				name:   "Apple_APFS_ISC",
				first:  gptPartStart / gptLBASize,
				end:    gptPartStart/gptLBASize + uint64(st.Size())/gptLBASize - 1,
			},
			{
				typ:    "7C3457EF-0000-11AA-AA11-00306543ECAC",
				unique: "49534300-0000-4000-8000-0000000000e2",
				name:   "Apple_APFS",
				first:  mainFirst,
				end:    mainFirst + mainLBAs - 1,
			},
		}
		must(writeGPT(f, totalLBAs, parts))
		must(copyAt(f, gptPartStart, *iscPath))
		cw = &offsetWriter{f: f, off: offset}
		fmt.Fprintf(os.Stderr, "GPT: iSC %d MiB at 0x%x, main %d MiB at 0x%x, disk %d MiB\n",
			st.Size()>>20, int64(gptPartStart), *size>>20, offset, totalLen>>20)
	}

	fmt.Fprintf(os.Stderr, "writing %s (%d bytes, %d volumes)...\n", *out, *size, len(specs))
	var ms2 runtime.MemStats
	runtime.ReadMemStats(&ms2)
	fmt.Fprintf(os.Stderr, "[pre-write] heap=%dMB sys=%dMB\n",
		ms2.HeapAlloc>>20, ms2.Sys>>20)
	elapsed("starting container write")
	err = apfswrite.CreateContainer(cw, *size, &apfswrite.CreateOptions{Volumes: specs})
	if err != nil && strings.Contains(err.Error(), "sizing image") {
		// All real blocks are already on disk; only the final length is missing.
		fmt.Fprintln(os.Stderr, "sizing write refused; appending to full size")
		must(growTo(f, offset+*size))
		err = nil
	}
	must(err)
	elapsed("container write complete")
	if len(parts) > 0 {
		// NTFS3 refuses far writes past EOF, so grow first (usually the
		// container's final-byte write already did) and only then place
		// the backup GPT.
		must(growTo(f, totalLen))
		must(writeGPTBackup(f, totalLBAs, parts))
	}
	fmt.Fprintln(os.Stderr, "done")
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "FATAL:", err)
		os.Exit(1)
	}
}
