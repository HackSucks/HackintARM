// apfs snapshot — inspect APFS volume snapshots.
package cli

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfswrite"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/deploymenttheory/go-apfs-v2/pkg/fidelity"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// Volume-superblock field offsets (bytes) used by in-place revert.
const (
	apsbRevertToXIDOffset    = 160
	apsbRevertToSblockOffset = 168
	nxMagicLE                = 0x4253584e // 'NXSB'
)

var snapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "List, create, verify and revert to APFS volume snapshots",
	Long: `Work with APFS snapshots.

Snapshots can also be created at build time with 'create --fs APFS --snapshot
NAME' or 'pack <dir> --fs APFS --snapshot NAME'.`,
}

func init() {
	snapshotCmd.AddCommand(snapshotListCmd)
	snapshotCmd.AddCommand(snapshotCreateCmd)
	snapshotCmd.AddCommand(snapshotVerifyCmd)
	snapshotCmd.AddCommand(snapshotRevertCmd)

	snapshotCreateCmd.Flags().StringVar(&snapCreateName, "name", "", "snapshot name (required)")
	snapshotCreateCmd.Flags().StringVarP(&snapCreateOutput, "output", "O", "", "write the result here (a new DMG)")
	snapshotCreateCmd.Flags().BoolVar(&snapCreateForce, "force", false, "overwrite the source image in place")
	snapshotCreateCmd.Flags().BoolVar(&snapCreateStrict, "strict", false, "refuse to write anything if the source volume holds something the rebuild cannot carry")
	snapCreateUUIDs.register(snapshotCreateCmd)

	snapshotRevertCmd.Flags().StringVar(&snapRevertName, "name", "", "snapshot to revert to (required)")
	snapshotRevertCmd.Flags().StringVarP(&snapRevertOutput, "output", "O", "", "write the result here (a new DMG)")
	snapshotRevertCmd.Flags().BoolVar(&snapRevertForce, "force", false, "overwrite the source image in place")
}

var (
	snapCreateName   string
	snapCreateOutput string
	snapCreateForce  bool
	snapCreateStrict bool
	snapCreateUUIDs  writeIdentityFlags
)

var snapshotCreateCmd = &cobra.Command{
	Use:   "create IMAGE --name NAME",
	Short: "Rebuild an APFS image carrying a snapshot of its current state",
	Long: `Read the APFS volume in IMAGE, rebuild it into a new APFS container that
additionally carries a snapshot named NAME capturing that state, and write the
result. The snapshot is a real, macOS-recognized APFS snapshot.

Because the writer rebuilds the volume from its contents (rather than preserving
the original on-disk bytes), this is not a byte-for-byte copy of the source. To
protect evidence, the result is written to --output by default; overwriting the
source in place requires --force.`,
	Args: exactArgs(1, "IMAGE"),
	RunE: runSnapshotCreate,
}

// resolveRebuildOutput returns where a rebuild command should write. To avoid
// destroying evidence, overwriting the source image requires --force.
func resolveRebuildOutput(image, output string, force bool) (string, error) {
	if output != "" {
		if output == image && !force {
			return "", usageErrorf("--output is the source image; pass --force to overwrite it in place")
		}
		return output, nil
	}
	if force {
		return image, nil
	}
	return "", usageErrorf("refusing to overwrite the source image; pass --output FILE (or --force to overwrite in place)")
}

func runSnapshotCreate(cmd *cobra.Command, args []string) error {
	if snapCreateName == "" {
		return usageErrorf("--name is required")
	}
	imagePath := args[0]
	outPath, err := resolveRebuildOutput(imagePath, snapCreateOutput, snapCreateForce)
	if err != nil {
		return err
	}

	container, cleanup, err := openAPFSContainer(imagePath)
	if err != nil {
		return err
	}
	defer cleanup()

	sel := opts.Volume
	if sel == "" {
		sel = "0"
	}
	volume, err := container.VolumeBySelector(sel)
	if err != nil {
		return withCode(ExitBadImage, fmt.Errorf("unable to open volume %q: %w", sel, err))
	}
	volName, _ := volume.UTF8Name()

	tree, report, err := entryTreeFromVolume(volume, fidelityWarner())
	if err != nil {
		return fmt.Errorf("unable to read volume contents: %w", err)
	}
	if err := enforceStrict(report, snapCreateStrict, imagePath); err != nil {
		return err
	}

	containerUUID, volumeUUID, err := snapCreateUUIDs.resolve()
	if err != nil {
		return err
	}
	fixed, clamp := writerTimes()

	copts := &apfswrite.CreateOptions{
		VolumeName:    volName,
		Root:          tree,
		Snapshots:     []apfswrite.SnapshotSpec{{Name: snapCreateName}},
		ContainerUUID: containerUUID,
		VolumeUUID:    volumeUUID,
		FixedTime:     fixed,
		ClampModTimes: clamp,
	}
	if ci, err := volume.IsCaseInsensitive(); err == nil {
		copts.CaseSensitive = !ci
	}

	img, err := newScratchImage(outPath)
	if err != nil {
		return err
	}
	defer img.Close()

	if err := apfswrite.CreateContainer(img, 0, copts); err != nil {
		return fmt.Errorf("unable to build APFS container with snapshot: %w", err)
	}
	if err := disk.WrapRawImageDMGFrom(outPath, img, img.Size(), "Apple_APFS", nil); err != nil {
		return fmt.Errorf("unable to write %s: %w", outPath, err)
	}

	if opts.Output == "json" {
		out := map[string]any{"source": imagePath, "destination": outPath, "snapshot": snapCreateName, "volume": volName}
		for key, value := range report.JSON() {
			out[key] = value
		}
		if err := jsonOut(out); err != nil {
			return err
		}
		return fidelityExit(report)
	}
	if !opts.Quiet {
		fmt.Printf("Wrote %s with snapshot %q of volume %q\n", outPath, snapCreateName, volName)
	}
	printFidelityNotes(report)
	return fidelityExit(report)
}

// entryTreeFromVolume walks an APFS volume and builds an apfswrite.Entry tree
// (files, directories, symlinks with their modes and independent times) that
// the writer can rebuild, along with an account of what the rebuild drops.
// Root timestamps are captured separately; other root metadata remains synthetic.
//
// This is the volume-to-volume counterpart of the writers' EntryTreeFromDir,
// and it loses the same things for the same reasons — plus the volume's own
// role and group membership, which a rebuilt volume does not inherit.
func entryTreeFromVolume(vol *apfs.Volume, warn func(string, fidelity.Kind, string)) (*apfswrite.Entry, *fidelity.Report, error) {
	w := &volumeWalker{vol: vol, report: &fidelity.Report{}, warn: warn}
	children, err := w.readDir(".")
	if err != nil {
		return nil, w.report, err
	}
	w.noteVolumeIdentity()
	times, err := vol.FileTimes(".")
	if err != nil {
		return nil, w.report, err
	}
	flags, err := vol.BSDFlags(".")
	if err != nil {
		return nil, w.report, err
	}
	flags &^= apfs.BSDFlagCompressed
	return &apfswrite.Entry{Children: children, Times: &times, BSDFlags: &flags}, w.report, nil
}

type volumeWalker struct {
	vol    *apfs.Volume
	report *fidelity.Report
	warn   func(string, fidelity.Kind, string)
}

func (w *volumeWalker) add(path string, kind fidelity.Kind, detail string) {
	w.report.Add(kind, path)
	if w.warn != nil {
		w.warn(path, kind, detail)
	}
}

// noteVolumeIdentity records the volume-level metadata a rebuild does not
// carry. The writer can set a role and a group, but a group needs its system
// and data halves in one container and this writer emits a single volume, so
// reproducing the source volume's identity is not generally possible.
func (w *volumeWalker) noteVolumeIdentity() {
	if role, err := w.vol.Role(); err == nil && role != apfs.VolumeRoleNone {
		w.add(".", fidelity.VolumeIdentity, "role "+apfs.VolumeRoleString(role))
	}
	if group, err := w.vol.VolumeGroupIdentifier(); err == nil && group != ([16]byte{}) {
		w.add(".", fidelity.VolumeIdentity, "volume group membership")
	}
}

func (w *volumeWalker) readDir(dir string) ([]*apfswrite.Entry, error) {
	des, err := w.vol.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []*apfswrite.Entry
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
		mode := info.Mode()
		times, err := w.vol.FileTimes(full)
		if err != nil {
			return nil, err
		}
		flags, err := w.vol.BSDFlags(full)
		if err != nil {
			return nil, err
		}
		// Rebuild reads expanded data and drops xattrs, so compression is no longer present.
		flags &^= apfs.BSDFlagCompressed
		e := &apfswrite.Entry{Name: name, Mode: mode, ModeExplicit: true, ModTime: info.ModTime(), Times: &times, BSDFlags: &flags}
		if inode, ok := info.Sys().(*apfs.Inode); ok {
			e.UID, e.GID = inode.OwnerIdentifier, inode.GroupIdentifier
			// A link count above one means the source had several names for
			// this inode; the rebuild gives each its own copy. Directories
			// legitimately exceed one because of their children's "..".
			if mode.IsRegular() && inode.NumberOfLinks > 1 {
				w.add(full, fidelity.HardLink, fmt.Sprintf("%d names in the source", inode.NumberOfLinks))
			}
		}
		w.noteAttributes(full)

		switch {
		case mode&fs.ModeSymlink != 0:
			target, err := w.vol.Readlink(full)
			if err != nil {
				return nil, fmt.Errorf("%s: reading symlink: %w", full, err)
			}
			e.Data = []byte(target)
		case mode.IsDir():
			kids, err := w.readDir(full)
			if err != nil {
				return nil, err
			}
			e.Children = kids
		case mode.IsRegular():
			data, err := w.vol.ReadFile(full)
			if err != nil {
				return nil, fmt.Errorf("%s: reading file: %w", full, err)
			}
			e.Data = data
		default:
			// The writer models only files, directories and symbolic links.
			w.add(full, fidelity.SpecialFile, mode.Type().String())
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// noteAttributes records the extended attributes the rebuild will not carry.
// The symlink attribute is excluded: it is how APFS stores a link target, which
// the rebuild does reproduce, so counting it would report a loss that is not one.
func (w *volumeWalker) noteAttributes(path string) {
	attrs, err := w.vol.Xattrs(path)
	if err != nil {
		return
	}
	for name := range attrs {
		switch {
		case name == symlinkXattrName:
			continue
		case name == hostdata.ResourceForkName:
			w.add(path, fidelity.ResourceFork, name)
		case hostdata.IsACLName(name):
			w.add(path, fidelity.ACL, name)
		default:
			w.add(path, fidelity.Xattr, name)
		}
	}
}

// symlinkXattrName is where APFS keeps a symbolic link's target. It is file
// system bookkeeping rather than user metadata, and the rebuild recreates it.
const symlinkXattrName = "com.apple.fs.symlink"

var snapshotVerifyCmd = &cobra.Command{
	Use:   "verify IMAGE",
	Short: "Verify that each snapshot in an APFS image is readable",
	Long: `Open each snapshot on each APFS volume and confirm its volume superblock and
metadata are readable. Reports the number of snapshots verified; exits non-zero
if any snapshot cannot be opened.`,
	Args: exactArgs(1, "IMAGE"),
	RunE: runSnapshotVerify,
}

func runSnapshotVerify(cmd *cobra.Command, args []string) error {
	container, cleanup, err := openAPFSContainer(args[0])
	if err != nil {
		return err
	}
	defer cleanup()

	volumes, err := container.Volumes()
	if err != nil {
		return fmt.Errorf("unable to enumerate volumes: %w", err)
	}

	var verified int
	var problems []string
	for vi, volume := range volumes {
		n, err := volume.NumberOfSnapshots()
		if err != nil {
			problems = append(problems, fmt.Sprintf("volume %d: %v", vi, err))
			continue
		}
		for i := 0; i < n; i++ {
			snap, err := volume.Snapshot(i)
			if err != nil {
				problems = append(problems, fmt.Sprintf("volume %d snapshot %d: %v", vi, i, err))
				continue
			}
			if snap.VolumeSuperblock == nil {
				problems = append(problems, fmt.Sprintf("volume %d snapshot %d: no superblock", vi, i))
				continue
			}
			verified++
		}
	}

	if opts.Output == "json" {
		if err := jsonOut(map[string]any{"verified": verified, "problems": problems}); err != nil {
			return err
		}
	} else if !opts.Quiet {
		fmt.Printf("Verified %d snapshot(s).\n", verified)
		for _, p := range problems {
			fmt.Fprintf(os.Stderr, "problem: %s\n", p)
		}
	}
	if len(problems) > 0 {
		return withCode(ExitError, fmt.Errorf("%d snapshot problem(s)", len(problems)))
	}
	return nil
}

var (
	snapRevertName   string
	snapRevertOutput string
	snapRevertForce  bool
)

var snapshotRevertCmd = &cobra.Command{
	Use:   "revert IMAGE --name NAME",
	Short: "Mark an APFS image to revert to a snapshot on next mount",
	Long: `Set the live volume's revert-to fields (apfs_revert_to_xid and
apfs_revert_to_sblock_oid) so that APFS rolls the volume back to snapshot NAME
the next time it is mounted — the spec's snapshot-revert mechanism.

The revert intent is patched into the live volume superblock in place (the rest
of the image is copied unchanged, so it is byte-faithful except for that one
block). The result is written to --output by default; overwriting the source in
place requires --force. Currently supports a DMG wrapping an APFS container at
offset zero (as produced by 'create'/'pack').`,
	Args: exactArgs(1, "IMAGE"),
	RunE: runSnapshotRevert,
}

// resolveLiveVolumeBlock returns the physical block of the live volume
// superblock for the given volume object id, mirroring how the container opens
// a volume (checkpoint map first, then the object map).
func resolveLiveVolumeBlock(c *apfs.Container, volID uint64) (uint64, error) {
	if addr, err := c.CheckpointMap.PhysicalAddressByObjectIdentifier(volID); err == nil && addr != 0 {
		return addr, nil
	}
	desc, err := c.ObjectMapBTree.DescriptorByObjectIdentifier(c.Reader, volID, c.Superblock.XID)
	if err != nil {
		return 0, err
	}
	return desc.Value.ObjectPhysicalAddress, nil
}

func runSnapshotRevert(cmd *cobra.Command, args []string) error {
	if snapRevertName == "" {
		return usageErrorf("--name is required")
	}
	imagePath := args[0]
	outPath, err := resolveRebuildOutput(imagePath, snapRevertOutput, snapRevertForce)
	if err != nil {
		return err
	}

	container, cleanup, err := openAPFSContainer(imagePath)
	if err != nil {
		return err
	}

	// Find the named snapshot (its xid and volume superblock address) and the live
	// volume's superblock block.
	volIDs, err := container.VolumeObjectIdentifiers()
	if err != nil || len(volIDs) == 0 {
		cleanup()
		return withCode(ExitBadImage, fmt.Errorf("unable to read volumes: %w", err))
	}
	volID := volIDs[0]
	volume, err := container.VolumeBySelector("0")
	if err != nil {
		cleanup()
		return withCode(ExitBadImage, fmt.Errorf("unable to open volume: %w", err))
	}

	var snapXID, snapSblock uint64
	found := false
	if n, _ := volume.NumberOfSnapshots(); n > 0 {
		for i := 0; i < n; i++ {
			snap, err := volume.Snapshot(i)
			if err != nil {
				continue
			}
			if name, _ := snap.UTF8Name(); name == snapRevertName && snap.SnapshotMetadata != nil {
				snapXID = snap.SnapshotMetadata.XID
				snapSblock = snap.SnapshotMetadata.VolumeSuperblockOID
				found = true
				break
			}
		}
	}
	if !found {
		cleanup()
		return withCode(ExitError, fmt.Errorf("no snapshot named %q on the volume", snapRevertName))
	}

	liveBlock, err := resolveLiveVolumeBlock(container, volID)
	if err != nil {
		cleanup()
		return fmt.Errorf("unable to locate the live volume superblock: %w", err)
	}
	blockSize := uint64(container.IOHandle.BlockSize)
	cleanup() // done reading; reconstruct and patch the raw image below

	// Reconstruct into a scratch file rather than memory: the image can be far
	// larger than RAM, and only one block of it is actually being changed.
	img, err := newScratchImage(outPath)
	if err != nil {
		return err
	}
	defer img.Close()

	total, err := disk.ReconstructRawImageTo(img, imagePath)
	if err != nil {
		return fmt.Errorf("revert currently requires a DMG image: %w", err)
	}

	// This patch addresses the container at offset zero in the raw image.
	magic := make([]byte, 4)
	if total < 36 {
		return withCode(ExitUnsupported, fmt.Errorf("revert supports a DMG wrapping an APFS container at offset zero"))
	}
	if _, err := img.ReadAt(magic, 32); err != nil {
		return fmt.Errorf("reading the container magic: %w", err)
	}
	if binary.LittleEndian.Uint32(magic) != nxMagicLE {
		return withCode(ExitUnsupported, fmt.Errorf("revert supports a DMG wrapping an APFS container at offset zero"))
	}

	off := liveBlock * blockSize
	if off+blockSize > uint64(total) {
		return fmt.Errorf("live volume superblock block %d is out of range", liveBlock)
	}
	block := make([]byte, blockSize)
	if _, err := img.ReadAt(block, int64(off)); err != nil {
		return fmt.Errorf("reading the live volume superblock: %w", err)
	}
	binary.LittleEndian.PutUint64(block[apsbRevertToXIDOffset:], snapXID)
	binary.LittleEndian.PutUint64(block[apsbRevertToSblockOffset:], snapSblock)
	// Reseal the block: Fletcher 64 over everything after the 8-byte checksum.
	cksum, err := apfs.CalculateFletcher64(block[8:], 0)
	if err != nil {
		return fmt.Errorf("recomputing superblock checksum: %w", err)
	}
	binary.LittleEndian.PutUint64(block[0:], cksum)
	if _, err := img.WriteAt(block, int64(off)); err != nil {
		return fmt.Errorf("writing the patched superblock: %w", err)
	}

	if err := disk.WrapRawImageDMGFrom(outPath, img, total, "Apple_APFS", nil); err != nil {
		return fmt.Errorf("unable to write %s: %w", outPath, err)
	}

	if opts.Output == "json" {
		return jsonOut(map[string]any{"source": imagePath, "destination": outPath, "revertTo": snapRevertName, "xid": snapXID})
	}
	if !opts.Quiet {
		fmt.Printf("Wrote %s marked to revert to snapshot %q (xid %d) on next mount\n", outPath, snapRevertName, snapXID)
	}
	return nil
}

var snapshotListCmd = &cobra.Command{
	Use:   "list IMAGE",
	Short: "List the snapshots on each APFS volume in an image",
	Args:  exactArgs(1, "IMAGE"),
	RunE:  runSnapshotList,
}

// openAPFSContainer opens imagePath as an APFS container (sniffing the DMG/raw
// layout and applying --offset), returning the container and a cleanup function.
// It is APFS-only: snapshots are an APFS concept.
func openAPFSContainer(imagePath string) (*apfs.Container, func(), error) {
	if _, err := os.Stat(imagePath); err != nil {
		return nil, nil, withCode(ExitBadImage, fmt.Errorf("unable to open image: %w", err))
	}
	reader, sniffedOffset, closer, err := disk.OpenWithOffset(imagePath)
	if err != nil {
		return nil, nil, withCode(ExitBadImage, fmt.Errorf("unable to open image: %w", err))
	}

	offset := opts.Offset
	if offset == 0 {
		offset = sniffedOffset
	}
	base := io.ReaderAt(reader)
	if offset != 0 {
		base = io.NewSectionReader(reader, offset, math.MaxInt64-offset)
	}
	if sniffFileSystem(base) != "apfs" {
		closer.Close()
		return nil, nil, withCode(ExitUnsupported, fmt.Errorf("%s is not an APFS image; snapshots are APFS-only", imagePath))
	}

	container, err := apfs.Open(base, &apfs.OpenOptions{
		Password:         opts.Password,
		RecoveryPassword: opts.RecoveryPassword,
	})
	if err != nil {
		closer.Close()
		return nil, nil, withCode(ExitBadImage, fmt.Errorf("unable to open APFS container: %w", err))
	}
	return container, func() { container.Close(); closer.Close() }, nil
}

// snapshotJSON is one snapshot in the JSON output.
type snapshotJSON struct {
	Volume      int       `json:"volume"`
	VolumeName  string    `json:"volumeName"`
	Name        string    `json:"name"`
	XID         uint64    `json:"xid"`
	CreatedTime time.Time `json:"created,omitempty"`
}

func runSnapshotList(cmd *cobra.Command, args []string) error {
	container, cleanup, err := openAPFSContainer(args[0])
	if err != nil {
		return err
	}
	defer cleanup()

	volumes, err := container.Volumes()
	if err != nil {
		return fmt.Errorf("unable to enumerate volumes: %w", err)
	}

	var out []snapshotJSON
	for vi, volume := range volumes {
		volName, _ := volume.UTF8Name()
		n, err := volume.NumberOfSnapshots()
		if err != nil {
			return fmt.Errorf("volume %d: unable to read snapshots: %w", vi, err)
		}
		for i := 0; i < n; i++ {
			snap, err := volume.Snapshot(i)
			if err != nil {
				return fmt.Errorf("volume %d snapshot %d: %w", vi, i, err)
			}
			name, _ := snap.UTF8Name()
			s := snapshotJSON{Volume: vi, VolumeName: volName, Name: name}
			if snap.SnapshotMetadata != nil {
				s.XID = snap.SnapshotMetadata.XID
				if t := snap.SnapshotMetadata.CreationTime; t != 0 {
					s.CreatedTime = time.Unix(0, int64(t)).UTC()
				}
			}
			out = append(out, s)
		}
	}

	if opts.Output == "json" {
		return jsonOut(out)
	}
	if len(out) == 0 {
		if !opts.Quiet {
			fmt.Println("No snapshots.")
		}
		return nil
	}
	for _, s := range out {
		created := ""
		if !s.CreatedTime.IsZero() {
			created = "  " + s.CreatedTime.Format(time.RFC3339)
		}
		fmt.Printf("Volume %d (%s): %s  (xid %d)%s\n", s.Volume, s.VolumeName, s.Name, s.XID, created)
	}
	return nil
}
