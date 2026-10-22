package main

import (
	"flag"
	"fmt"
	"io"
	"os"
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
			if inode.NumberOfLinks > 1 {
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

func dataSkeleton() *apfswrite.Entry {
	return &apfswrite.Entry{Children: []*apfswrite.Entry{
		dirEntry("private",
			dirEntry("var",
				dirEntry("db"), dirEntry("log"), dirEntry("run"), dirEntry("tmp"),
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

func main() {
	src := flag.String("src", "", "source APFS image")
	out := flag.String("out", "", "output container image")
	size := flag.Int64("size", 0, "container size in bytes")
	subtree := flag.String("subtree", ".", "subtree to copy (as the new volume root)")
	noExtra := flag.Bool("noextra", false, "omit Data/Preboot volumes (fidelity testing)")
	dry := flag.Bool("dry", false, "walk only")
	flag.Parse()

	container, closer, err := apfs.OpenImage(*src, nil)
	must(err)
	defer closer.Close()

	vol, err := container.VolumeBySelector("0")
	must(err)

	volUUID, err := vol.Identifier()
	must(err)
	group := [16]byte{0x7a, 0x1c, 0x9e, 0x42, 0x3b, 0x5d, 0x4f, 0x60, 0x9d, 0x2e, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}

	w := &walker{vol: vol, skip: map[string]int{}}
	kids, err := w.children(*subtree)
	must(err)
	root := &apfswrite.Entry{Children: kids}
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
			apfswrite.VolumeSpec{Name: "Macintosh HD - Data", Role: apfs.VolumeRoleData, VolumeGroupID: group, Root: dataSkeleton()},
			apfswrite.VolumeSpec{Name: "Preboot", Role: apfs.VolumeRolePreboot, Root: &apfswrite.Entry{Children: []*apfswrite.Entry{
				dirEntry(uuidString(group), dirEntry("boot"), dirEntry("cryptex1"), dirEntry("restore")),
			}}},
		)
	}

	f, err := os.Create(*out)
	must(err)
	defer f.Close()

	fmt.Fprintf(os.Stderr, "writing %s (%d bytes, %d volumes)...\n", *out, *size, len(specs))
	err = apfswrite.CreateContainer(f, *size, &apfswrite.CreateOptions{Volumes: specs})
	if err != nil && strings.Contains(err.Error(), "sizing image") {
		// All real blocks are already on disk; only the final length is missing.
		fmt.Fprintln(os.Stderr, "sizing write refused; appending to full size")
		must(growTo(f, *size))
		err = nil
	}
	must(err)
	fmt.Fprintln(os.Stderr, "done")
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "FATAL:", err)
		os.Exit(1)
	}
}
