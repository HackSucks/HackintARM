// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors
//
// mkisc builds the auxiliary-storage ("iSC") container as a GPT disk.
//
// On Apple Silicon the internal disk is one GPT disk whose first partition is
// the iSC container (type 69646961-6700-11AA-AA11-00306543ECAC).  It holds the
// volumes macOS mounts early in mount-phase-1:
//
//	iSCPreboot	role Preboot  (0x10)
//	xART		role XART     (0x100)
//	Hardware	role Hardware (0x140)
//
// mount_phase_one() looks the partition up by IOKit's "Content Hint", which
// IOGUIDPartitionScheme publishes as the partition type GUID string, so the
// type GUID *is* the contract.  Its xART mount is fatal: without the volume
// apfs_boot_util aborts and launchd never leaves mount-phase-1.
//
// The image is deliberately sparse: apfswrite writes the blocks it uses and a
// final byte, and the rest of the file stays a hole.  Attach it as an ordinary
// virtio-blk disk (QEMU) or through whatever block device Trestle models; the
// guest does not care which, only about the GPT type and the container.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"hash/crc32"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
)

const (
	lbaSize      = 512
	partStart    = 1 << 20 // 1 MiB, the usual GPT alignment
	gptEntries   = 128
	gptEntrySize = 128
)

// offsetWriter puts the APFS container at a partition offset.
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

// putGuid is the reverse of guidBytes, for the header fields.
// putGuid stores a GUID the way GPT does.  guidBytes already produced the
// on-disk byte order (EFI GUID: Data1/2/3 little-endian), so this is a plain
// copy; swapping here again would store the type GUID in the wrong order and
// the partition's IOKit "Content Hint" would name a partition type no driver
// matches.
func putGuid(dst []byte, g [16]byte) {
	copy(dst[:16], g[:])
}

func crc(b []byte) uint32 { return crc32.ChecksumIEEE(b) }

// writeGPT writes the protective MBR, the primary GPT (header + entries), and
// leaves the backup area at the end of the file to writeGPTBackup.
func writeGPT(f *os.File, totalLBAs uint64, typeGUID, partGUID, diskGUID [16]byte, firstLBA, lastLBA uint64) error {
	mbr := make([]byte, lbaSize)
	mbr[446] = 0x00
	mbr[447], mbr[448], mbr[449] = 0x00, 0x02, 0x00
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

	entries := make([]byte, gptEntries*gptEntrySize)
	putGuid(entries[0:16], typeGUID)
	putGuid(entries[16:32], partGUID)
	binary.LittleEndian.PutUint64(entries[32:], firstLBA)
	binary.LittleEndian.PutUint64(entries[40:], lastLBA)
	name := "Apple_APFS_ISC"
	for i := 0; i < len(name) && i < 36; i++ {
		entries[56+i*2] = name[i]
	}
	// The unused entries keep their zero GUIDs; only entry 0 is used.
	if _, err := f.WriteAt(entries, 2*lbaSize); err != nil {
		return err
	}

	hdr := make([]byte, 92)
	copy(hdr[0:], "EFI PART")
	binary.LittleEndian.PutUint32(hdr[8:], 0x00010000)
	binary.LittleEndian.PutUint32(hdr[12:], 92)
	binary.LittleEndian.PutUint64(hdr[24:], 1)
	binary.LittleEndian.PutUint64(hdr[32:], totalLBAs-1)
	binary.LittleEndian.PutUint64(hdr[40:], 34)
	binary.LittleEndian.PutUint64(hdr[48:], totalLBAs-34)
	putGuid(hdr[56:72], diskGUID)
	binary.LittleEndian.PutUint64(hdr[72:], 2)
	binary.LittleEndian.PutUint32(hdr[80:], gptEntries)
	binary.LittleEndian.PutUint32(hdr[84:], gptEntrySize)
	binary.LittleEndian.PutUint32(hdr[88:], crc(entries))
	binary.LittleEndian.PutUint32(hdr[16:], crc(hdr))
	if _, err := f.WriteAt(hdr, lbaSize); err != nil {
		return err
	}

	// Backup entries and header at the end of the disk.
	if _, err := f.WriteAt(entries, int64((totalLBAs-33)*lbaSize)); err != nil {
		return err
	}
	binary.LittleEndian.PutUint64(hdr[24:], totalLBAs-1)
	binary.LittleEndian.PutUint64(hdr[32:], 1)
	binary.LittleEndian.PutUint64(hdr[72:], totalLBAs-33)
	binary.LittleEndian.PutUint32(hdr[16:], 0)
	binary.LittleEndian.PutUint32(hdr[16:], crc(hdr))
	_, err := f.WriteAt(hdr, int64((totalLBAs-1)*lbaSize))
	return err
}

func dirEntry(name string) *apfswrite.Entry {
	return &apfswrite.Entry{Name: name, Mode: os.ModeDir | 0755, ModeExplicit: true, UID: 0, GID: 0}
}

func main() {
	out := flag.String("out", "isc.img", "output image")
	sizeMiB := flag.Int64("size", 1536, "APFS container size in MiB (>= 512 per volume)")
	containerOnly := flag.Bool("container", false, "write the bare APFS container (no GPT)")
	flag.Parse()

	if *sizeMiB < 512 || *sizeMiB%512 != 0 {
		fmt.Fprintln(os.Stderr, "size must be a multiple of 512 MiB (512 MiB per volume)")
		os.Exit(2)
	}

	containerSize := *sizeMiB << 20
	firstLBA := uint64(partStart / lbaSize)
	partLBAs := uint64(containerSize / lbaSize)
	lastLBA := firstLBA + partLBAs - 1
	// One MiB of backup GPT at the end.
	totalLBAs := (uint64(partStart) + uint64(containerSize) + 1<<20) / lbaSize
	if totalLBAs%2048 != 0 {
		totalLBAs += 2048 - totalLBAs%2048
	}

	iscType, err := guidBytes("69646961-6700-11AA-AA11-00306543ECAC")
	must(err)
	diskGUID, err := guidBytes("49534300-0000-4000-8000-0000000000d0")
	must(err)
	partGUID := diskGUID
	partGUID[15] = 0x01

	containerUUID, err := guidBytes("49534300-0000-4000-8000-0000000000c1")
	must(err)
	iscPrebootUUID, err := guidBytes("49534300-0000-4000-8000-0000000000c2")
	must(err)
	xartUUID, err := guidBytes("49534300-0000-4000-8000-0000000000c3")
	must(err)
	hardwareUUID, err := guidBytes("49534300-0000-4000-8000-0000000000c4")
	must(err)

	f, err := os.Create(*out)
	must(err)
	defer f.Close()

	offset := int64(partStart)
	if *containerOnly {
		offset = 0
		totalLBAs = partLBAs
	} else {
		must(writeGPT(f, totalLBAs, iscType, partGUID, diskGUID, firstLBA, lastLBA))
	}

	specs := []apfswrite.VolumeSpec{
		{Name: "iSCPreboot", UUID: iscPrebootUUID, Role: apfs.VolumeRolePreboot,
			Root: &apfswrite.Entry{Children: []*apfswrite.Entry{dirEntry(".exclave")}}},
		{Name: "xART", UUID: xartUUID, Role: apfs.VolumeRoleXART},
		{Name: "Hardware", UUID: hardwareUUID, Role: apfs.VolumeRoleHardware},
	}
	w := &offsetWriter{f: f, off: offset}
	where := "at 0x" + strconv.FormatInt(offset, 16)
	if *containerOnly {
		where = "bare"
	}
	fmt.Fprintf(os.Stderr, "writing %s: %d MiB container %s, image %d MiB, uuid %s\n",
		*out, *sizeMiB, where, totalLBAs*lbaSize>>20, uuidString(containerUUID))
	err = apfswrite.CreateContainer(w, containerSize, &apfswrite.CreateOptions{
		ContainerUUID: containerUUID,
		Volumes:       specs,
		FixedTime:     time.Unix(0, 0).UTC(),
	})
	must(err)

	// Fill the trailing hole out to the backup GPT (or to the container end).
	must(f.Truncate(int64(totalLBAs * lbaSize)))
	must(f.Sync())
	fmt.Fprintln(os.Stderr, "done")
}

func uuidString(u [16]byte) string {
	return fmt.Sprintf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
		u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15])
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "FATAL:", err)
		os.Exit(1)
	}
}
