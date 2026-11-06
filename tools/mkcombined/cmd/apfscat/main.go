// apfscat reads files out of an APFS image through the same go-apfs reader
// mkcombined uses.  It exists for offline diagnosis: point it at a merged
// disk image (a qcow2 exposed through qemu-storage-daemon's FUSE export, or a
// raw image) and read any path, on any volume, without booting the guest.
//
//	go run ./cmd/apfscat <image> <volume> cat  <path>
//	go run ./cmd/apfscat <image> <volume> ls   <path>
//	go run ./cmd/apfscat <image> <volume> stat <path>
//	go run ./cmd/apfscat <image> <volume> xattr <path>
//	go run ./cmd/apfscat <image> <volume> tree <path> [depth]
//
// <volume> is an index, a volume name, "role:system", "role:data", or a UUID.
package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "apfscat:", err)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: apfscat <image> <volume> <cat|ls|stat|xattr|tree> [path] [depth]")
		os.Exit(2)
	}
	img, sel, op := os.Args[1], os.Args[2], os.Args[3]
	p := "."
	if len(os.Args) > 4 {
		p = os.Args[4]
	}

	c, closer, err := apfs.OpenImage(img, nil)
	if err != nil {
		fatal(err)
	}
	defer closer.Close()

	v, err := c.VolumeBySelector(sel)
	if err != nil {
		fatal(err)
	}
	if n, err := v.UTF8Name(); err == nil {
		fmt.Fprintf(os.Stderr, "apfscat: volume %q\n", n)
	}

	switch op {
	case "ls":
		des, err := v.ReadDir(p)
		if err != nil {
			fatal(err)
		}
		sort.Slice(des, func(i, j int) bool { return des[i].Name() < des[j].Name() })
		for _, de := range des {
			fi, err := de.Info()
			if err != nil {
				fmt.Printf("? ? %s\n", de.Name())
				continue
			}
			fmt.Printf("%s %12d %s\n", fi.Mode(), fi.Size(), de.Name())
		}
	case "cat":
		data, err := v.ReadFile(p)
		if err != nil {
			fatal(err)
		}
		os.Stdout.Write(data)
	case "stat":
		fi, err := v.Stat(p)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("%s size=%d mode=%s\n", fi.Name(), fi.Size(), fi.Mode())
	case "xattr":
		m, err := v.Xattrs(p)
		if err != nil {
			fatal(err)
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			val := m[k]
			show := val
			if len(show) > 64 {
				show = show[:64]
			}
			fmt.Printf("%s (%d) %s\n", k, len(val), hex.EncodeToString(show))
		}
	case "inode":
		fi, err := v.Stat(p)
		if err != nil {
			fatal(err)
		}
		in, _ := fi.Sys().(*apfs.Inode)
		if in == nil {
			fatal(fmt.Errorf("%s: no inode", p))
		}
		fmt.Printf("name=%s id=%d parent=%d links=%d bsdflags=0x%x mode=%o uid=%d gid=%d dsid=0x%x dssize=%d\n",
			in.Name, in.Identifier, in.ParentIdentifier, in.NumberOfLinks, in.BSDFlags,
			in.FileMode, in.OwnerIdentifier, in.GroupIdentifier, in.DataStreamIdentifier, in.DataStreamSize)
	case "links":
		depth := 200
		if len(os.Args) > 5 {
			fmt.Sscanf(os.Args[5], "%d", &depth)
		}
		printLinks(v, p, depth)
	case "tree":
		depth := 6
		if len(os.Args) > 5 {
			fmt.Sscanf(os.Args[5], "%d", &depth)
		}
		walk(v, p, 0, depth)
	default:
		fmt.Fprintln(os.Stderr, "unknown op", op)
		os.Exit(2)
	}
}

func printLinks(v *apfs.Volume, root string, max int) {
	var rec func(dir string, level int)
	rec = func(dir string, level int) {
		des, err := v.ReadDir(dir)
		if err != nil {
			return
		}
		for _, de := range des {
			fi, err := de.Info()
			if err != nil {
				continue
			}
			in, _ := fi.Sys().(*apfs.Inode)
			name := path.Join(dir, de.Name())
			if in != nil && in.NumberOfLinks > 1 && fi.Mode().IsRegular() {
				fmt.Printf("%d %d %d %s\n", in.NumberOfLinks, fi.Size(), in.Identifier, name)
			}
			if fi.IsDir() && level < max {
				rec(name, level+1)
			}
		}
	}
	rec(root, 0)
}

func walk(v *apfs.Volume, dir string, level, max int) {
	des, err := v.ReadDir(dir)
	if err != nil {
		fmt.Printf("%s%s: %v\n", strings.Repeat("  ", level), dir, err)
		return
	}
	sort.Slice(des, func(i, j int) bool { return des[i].Name() < des[j].Name() })
	for _, de := range des {
		fi, err := de.Info()
		if err != nil {
			continue
		}
		name := path.Join(dir, de.Name())
		suffix := ""
		if !fi.IsDir() {
			suffix = fmt.Sprintf("  %d", fi.Size())
		}
		fmt.Printf("%s%s%s\n", strings.Repeat("  ", level), de.Name(), suffix)
		if fi.IsDir() && level < max {
			walk(v, name, level+1, max)
		}
	}
	_ = io.Discard
}
