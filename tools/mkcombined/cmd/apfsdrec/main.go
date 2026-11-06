// apfsdrec dumps the raw file-system-tree directory-entry record and the
// sibling link/map records for one name in one directory, so a synthetic
// image's hardlink records can be diffed against Apple's.
//
//	go run ./cmd/apfsdrec <image> <volume> <dir> <name>
package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "apfsdrec:", err)
		os.Exit(1)
	}
}

func dumpRecords(v *apfs.Volume, oid uint64) {
	recs, err := v.FileSystemBTree.AllRecordsForOID(v.Reader, oid)
	if err != nil {
		fmt.Printf("oid %d: %v\n", oid, err)
		return
	}
	for _, r := range recs {
		typ, _ := apfs.ExtractDataTypeFromKey(r.KeyData)
		fmt.Printf("  oid=%d type=%d key=%s val=%s\n", oid, typ,
			hex.EncodeToString(r.KeyData), hex.EncodeToString(r.ValueData))
	}
}

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: apfsdrec <image> <volume> <dir> <name>")
		os.Exit(2)
	}
	img, vol, dirPath, name := os.Args[1], os.Args[2], os.Args[3], os.Args[4]

	c, closer, err := apfs.OpenImage(img, nil)
	must(err)
	defer closer.Close()

	v, err := c.VolumeBySelector(vol)
	must(err)

	di, err := v.Stat(dirPath)
	must(err)
	dirInode, _ := di.Sys().(*apfs.Inode)
	if dirInode == nil {
		must(fmt.Errorf("no inode for %s", dirPath))
	}
	fmt.Printf("dir=%s dir_ino=%d\n", dirPath, dirInode.Identifier)

	drec, err := v.FileSystemBTree.DirectoryEntryRecordByUTF8Name(v.Reader, dirInode.Identifier, name, 0)
	must(err)
	fmt.Printf("drec name=%s file_id=%d flags=0x%x fields=%d\n",
		drec.Name, drec.Identifier, drec.Flags, len(drec.ExtendedFields))
	for _, f := range drec.ExtendedFields {
		fmt.Printf("  xfield type=%d flags=0x%x data=%s\n", f.Type, f.Flags, hex.EncodeToString(f.Data))
	}

	fmt.Printf("records for inode oid %d:\n", drec.Identifier)
	dumpRecords(v, drec.Identifier)

	for _, f := range drec.ExtendedFields {
		if f.Type == apfs.DirectoryEntryExtendedFieldTypeSiblingID && len(f.Data) == 8 {
			sid := binary.LittleEndian.Uint64(f.Data)
			fmt.Printf("sibling_id=%d records:\n", sid)
			dumpRecords(v, sid)
		}
	}
}
