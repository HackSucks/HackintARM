// Shared image/volume opening for all commands.
package cli

import (
	"fmt"
	"io"
	"math"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/internal/tools"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hfsplus"
)

// volumeFS is the contract that list, cat and extract operate on. Both APFS
// volumes (pkg/apfs) and HFS+ volumes (pkg/hfsplus) implement it.
type volumeFS = tools.VolumeFS

// multiCloser closes several resources in order.
type multiCloser []io.Closer

func (m multiCloser) Close() error {
	var firstErr error
	for _, c := range m {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// freeCloser adapts the APFS container's Free method to io.Closer.
type freeCloser struct{ container *apfs.Container }

func (f freeCloser) Close() error { return f.container.Close() }

// sniffFileSystem identifies the file system at the start of a
// partition-relative reader: "apfs", "hfsplus" or "".
func sniffFileSystem(reader io.ReaderAt) string {
	magic := make([]byte, 4)
	if _, err := reader.ReadAt(magic, 32); err == nil && string(magic) == "NXSB" {
		return "apfs"
	}
	sig := make([]byte, 2)
	if _, err := reader.ReadAt(sig, 1024); err == nil && (string(sig) == "H+" || string(sig) == "HX") {
		return "hfsplus"
	}
	return ""
}

// detectFileSystem reports which file system an image holds: "apfs",
// "hfsplus" or "". It opens and closes the image, so callers that go on to
// read it pay for the open twice -- which is worth it for commands that must
// dispatch before they know what they are looking at.
func detectFileSystem(imagePath string) (string, error) {
	reader, sniffedOffset, closer, err := disk.OpenWithOffset(imagePath)
	if err != nil {
		return "", withCode(ExitBadImage, fmt.Errorf("unable to open image: %w", err))
	}
	defer closer.Close()

	offset := opts.Offset
	if offset == 0 {
		offset = sniffedOffset
	}
	base := io.ReaderAt(reader)
	if offset != 0 {
		base = io.NewSectionReader(reader, offset, math.MaxInt64-offset)
	}
	return sniffFileSystem(base), nil
}

// openFileSystem opens an image and returns the selected volume as a
// file system, dispatching on the detected file system type (APFS or HFS+).
func openFileSystem(imagePath string) (volumeFS, io.Closer, error) {
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

	switch sniffFileSystem(base) {
	case "apfs":
		container, err := apfs.Open(base, &apfs.OpenOptions{
			Password:         opts.Password,
			RecoveryPassword: opts.RecoveryPassword,
		})
		if err != nil {
			closer.Close()
			return nil, nil, withCode(ExitBadImage, fmt.Errorf("unable to open APFS container: %w", err))
		}
		volume, err := openVolume(container)
		if err != nil {
			container.Close()
			closer.Close()
			return nil, nil, err
		}
		return volume, multiCloser{freeCloser{container}, closer}, nil

	case "hfsplus":
		volume, err := hfsplus.New(base)
		if err != nil {
			closer.Close()
			return nil, nil, withCode(ExitBadImage, fmt.Errorf("unable to open HFS+ volume: %w", err))
		}
		if opts.Volume != "" && opts.Volume != "0" && opts.Volume != volume.Name() {
			closer.Close()
			return nil, nil, usageErrorf("no volume matches selector %q (HFS+ image contains the single volume %q)", opts.Volume, volume.Name())
		}
		return volume, closer, nil

	default:
		closer.Close()
		return nil, nil, withCode(ExitBadImage, fmt.Errorf("%s does not contain a recognizable APFS or HFS+ file system", imagePath))
	}
}

// openVolume opens the volume selected by --volume (default: first) and
// enforces the authentication contract (locked volumes exit 4).
func openVolume(container *apfs.Container) (*apfs.Volume, error) {
	volume, err := container.VolumeBySelector(opts.Volume)
	if err != nil {
		return nil, usageErrorf("%v", err)
	}

	if locked, err := volume.IsLocked(); err == nil && locked {
		if opts.Password == "" && opts.RecoveryPassword == "" {
			return nil, withCode(ExitAuth, fmt.Errorf("volume is encrypted; supply --password or --recovery-password"))
		}
		return nil, withCode(ExitAuth, fmt.Errorf("unable to unlock volume: wrong password"))
	}

	return volume, nil
}
