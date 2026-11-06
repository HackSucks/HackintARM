package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

func main() {
	img := os.Args[1]
	path := os.Args[2]
	c, closer, err := apfs.OpenImage(img, nil)
	if err != nil {
		panic(err)
	}
	defer closer.Close()
	vol, err := c.VolumeBySelector("0")
	if err != nil {
		panic(err)
	}

	if path == "fext" {
		fext(vol, os.Args[3])
		return
	}
	if path == "enum" {
		enumOID(vol, os.Args[3])
		return
	}
	comp, incomp, ro, err := vol.FeaturesFlags()
	if err != nil {
		panic(err)
	}
	name, _ := vol.UTF8Name()
	fmt.Printf("volume %q compat=%#x incompat=%#x ro=%#x\n", name, comp, incomp, ro)
	fe, err := vol.FileEntryByPath(path)
	if err != nil {
		panic(err)
	}
	in := fe.Inode
	fmt.Printf("inode id=%d parent=%d mode=%o flags=%#x bsd=%#x nlink=%d\n",
		in.Identifier, in.ParentIdentifier, in.FileMode, in.Flags, in.BSDFlags, in.NumberOfLinks)
	fmt.Printf("  DataStreamIdentifier=%d DataStreamSize=%d\n", in.DataStreamIdentifier, in.DataStreamSize)
	sz, err := fe.DataSize()
	fmt.Printf("  DataSize()=%d err=%v\n", sz, err)

	vals, verr := vol.XattrValues(path)
	fmt.Printf("  XattrValues err=%v keys=%d\n", verr, len(vals))
	for k := range vals {
		fmt.Printf("    xattr %q\n", k)
	}

	for _, id := range []uint64{in.Identifier, in.DataStreamIdentifier, 121, in.Identifier + 1} {
		if id == 0 {
			continue
		}
		recs, err := fe.FileSystemBTree.AllRecordsForOID(fe.FileHandle, id)
		fmt.Printf("  AllRecordsForOID(%d) -> %d records err=%v\n", id, len(recs), err)
		for i, r := range recs {
			if i > 6 {
				fmt.Printf("    ... %d more\n", len(recs)-i)
				break
			}
			fmt.Printf("    key=%x val=%x\n", r.KeyData, r.ValueData)
		}
	}

	recs, err := fe.FileSystemBTree.AllRecordsForOID(fe.FileHandle, 121)
	types := map[uint8]int{}
	for _, r := range recs {
		t, _ := apfs.ExtractDataTypeFromKey(r.KeyData)
		types[t]++
	}
	fmt.Printf("  OID121 record type histogram: %v\n", types)
	ext, err := fe.FileSystemBTree.FileExtents(fe.FileHandle, 121, fe.XID)
	fmt.Printf("  FileExtents(121) -> %d err=%v\n", len(ext), err)
	dr, err := fe.FileSystemBTree.AllRecordsForOID(fe.FileHandle, 120)
	t2 := map[uint8]int{}
	for _, r := range dr {
		t, _ := apfs.ExtractDataTypeFromKey(r.KeyData)
		t2[t]++
	}
	fmt.Printf("  OID120 record type histogram: %v\n", t2)

	f, err := vol.Open(path)
	if err != nil {
		fmt.Printf("  Open err=%v\n", err)
		return
	}
	ra := f.(io.ReaderAt)
	buf := make([]byte, 16)
	n, err := ra.ReadAt(buf, 0)
	fmt.Printf("  ReadAt(0) n=%d err=%v bytes=%x\n", n, err, buf[:n])
}

func enumOID(vol *apfs.Volume, oidStr string) {
	target, err := strconv.ParseUint(oidStr, 0, 64)
	if err != nil {
		panic(err)
	}
	root, err := vol.RootDirectory()
	if err != nil {
		panic(err)
	}
	bt := root.FileSystemBTree
	handle := root.FileHandle

	var walk func(n *apfs.BTreeNode)
	hist := map[string]int{}
	total := 0
	walk = func(n *apfs.BTreeNode) {
		if n == nil {
			return
		}
		if n.IsLeafNode() {
			for _, e := range n.Entries {
				if len(e.KeyData) < 8 {
					continue
				}
				hdr := binary.LittleEndian.Uint64(e.KeyData[:8])
				id := hdr & 0x0fffffffffffffff
				if id != target {
					continue
				}
				total++
				t := uint8((hdr >> 60) & 0xf)
				key := fmt.Sprintf("type=%d keylen=%d vallen=%d key=%x", t, len(e.KeyData), len(e.ValueData), e.KeyData)
				if len(hist) < 20 || hist[key] > 0 {
					hist[key]++
				} else {
					hist[key]++
				}
			}
			return
		}
		for _, e := range n.Entries {
			child, err := bt.SubNodeOIDFromEntry(handle, e)
			if err != nil {
				fmt.Printf("  subnode err: %v\n", err)
				continue
			}
			cn, err := bt.SubNode(handle, child)
			if err != nil {
				fmt.Printf("  subnode(%d) err: %v\n", child, err)
				continue
			}
			walk(cn)
		}
	}
	rn, err := bt.RootNode(handle)
	if err != nil {
		panic(err)
	}
	walk(rn)
	fmt.Printf("OID %d: %d records, %d distinct keys\n", target, total, len(hist))
	i := 0
	for k, v := range hist {
		fmt.Printf("  %dx %s\n", v, k)
		i++
		if i > 30 {
			fmt.Printf("  ... more\n")
			break
		}
	}
}

func fext(vol *apfs.Volume, blockStr string) {
	root, err := vol.RootDirectory()
	if err != nil {
		panic(err)
	}
	bt := root.FileSystemBTree
	handle := root.FileHandle
	var b uint64
	fmt.Sscanf(blockStr, "%d", &b)
	var walk func(blk uint64, depth int)
	walk = func(blk uint64, depth int) {
		n, err := bt.SubNode(handle, blk)
		if err != nil {
			fmt.Printf("  node %d err=%v\n", blk, err)
			return
		}
		ind := ""
		for i := 0; i < depth; i++ {
			ind += "  "
		}
		fmt.Printf("%snode blk=%d level=%d nkeys=%d objtype=%#x subtype=%#x flags=%#x\n",
			ind, blk, n.NodeHeader.Level, len(n.Entries), n.ObjectType, n.ObjectSubtype, n.NodeHeader.Flags)
		if n.NodeHeader.Level == 0 || len(n.Entries) == 0 || depth > 6 {
			for i, e := range n.Entries {
				if i > 5 {
					fmt.Printf("%s  ... %d more\n", ind, len(n.Entries)-i)
					break
				}
				fmt.Printf("%s  key(%d)=%x val(%d)=%x\n", ind, len(e.KeyData), e.KeyData, len(e.ValueData), e.ValueData)
			}
			return
		}
		for _, e := range n.Entries {
			if len(e.ValueData) < 8 {
				continue
			}
			child := binary.LittleEndian.Uint64(e.ValueData[:8])
			walk(child, depth+1)
		}
	}
	walk(b, 0)
}
