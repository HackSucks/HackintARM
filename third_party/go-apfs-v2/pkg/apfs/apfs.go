// Public entry points for opening APFS containers from images and readers.
package apfs

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/disk"
)

// OpenOptions configures Open and OpenImage.
type OpenOptions struct {
	// Offset is the byte offset of the container within the reader. For
	// OpenImage a non-zero value overrides the offset detected from the
	// image's partition table.
	Offset int64

	// Password unlocks encrypted volumes (user password).
	Password string

	// RecoveryPassword unlocks encrypted volumes (recovery password).
	RecoveryPassword string
}

// Open opens an APFS container from a reader. The container superblock is
// expected at opts.Offset (0 when the reader is already partition-relative,
// as disk.OpenWithOffset returns for DMGs).
func Open(reader io.ReaderAt, opts *OpenOptions) (*Container, error) {
	if opts == nil {
		opts = &OpenOptions{}
	}

	ioHandle, err := NewIOHandle()
	if err != nil {
		return nil, fmt.Errorf("unable to create IO handle: %w", err)
	}

	container, err := NewContainer(ioHandle)
	if err != nil {
		return nil, fmt.Errorf("unable to create container: %w", err)
	}

	if err := container.OpenRead(reader, opts.Offset); err != nil {
		return nil, fmt.Errorf("unable to open container: %w", err)
	}

	container.userPassword = opts.Password
	container.recoveryPassword = opts.RecoveryPassword

	return container, nil
}

// OpenImage opens an APFS container from a disk image file. The image format
// (DMG, GPT-partitioned raw image, or bare container) is detected from
// content. The returned closer releases the underlying image reader and must
// be closed after the container is no longer needed.
func OpenImage(path string, opts *OpenOptions) (*Container, io.Closer, error) {
	if opts == nil {
		opts = &OpenOptions{}
	}

	reader, sniffedOffset, closer, err := disk.OpenWithOffset(path)
	if err != nil {
		return nil, nil, err
	}

	offset := opts.Offset
	if offset == 0 {
		offset = sniffedOffset
	}

	openOpts := *opts
	openOpts.Offset = offset

	container, err := Open(reader, &openOpts)
	if err != nil {
		closer.Close()
		return nil, nil, err
	}

	return container, closer, nil
}

// Volumes returns all volumes in the container. Encrypted volumes are
// unlocked with the passwords given at open time when possible.
func (c *Container) Volumes() ([]*Volume, error) {
	count, err := c.NumberOfVolumes()
	if err != nil {
		return nil, err
	}

	volumes := make([]*Volume, 0, count)
	for index := range count {
		volume, err := c.Volume(index)
		if err != nil {
			return nil, fmt.Errorf("unable to open volume %d: %w", index, err)
		}
		c.applyPasswords(volume)
		volumes = append(volumes, volume)
	}

	return volumes, nil
}

// VolumeBySelector returns a single volume selected by index ("0"), name
// ("Macintosh HD"), UUID, or role ("system", or "role:system" to select by role
// explicitly). An empty selector returns the first volume.
//
// Name and UUID are matched before a bare role token, so a volume literally
// named "system" still wins; the "role:" prefix skips that check for callers
// that need to be unambiguous. A bare role token that matches several volumes
// is an error rather than a silent first-match: picking one arbitrarily is the
// wrong default for a tool used forensically.
func (c *Container) VolumeBySelector(selector string) (*Volume, error) {
	if selector == "" {
		selector = "0"
	}

	// Numeric selector: volume index
	if index, err := strconv.Atoi(selector); err == nil {
		volume, err := c.Volume(index)
		if err != nil {
			return nil, err
		}
		c.applyPasswords(volume)
		return volume, nil
	}

	volumes, err := c.Volumes()
	if err != nil {
		return nil, err
	}

	if role, ok := strings.CutPrefix(strings.ToLower(selector), "role:"); ok {
		return volumeByRole(volumes, role, selector)
	}

	for _, volume := range volumes {
		if name, err := volume.UTF8Name(); err == nil && name == selector {
			return volume, nil
		}
		if uuid, err := volume.Identifier(); err == nil && formatVolumeUUID(uuid) == strings.ToLower(selector) {
			return volume, nil
		}
	}

	// No name or UUID matched, so fall back to interpreting the selector as a
	// role token.
	if _, err := ParseVolumeRole(selector); err == nil {
		return volumeByRole(volumes, strings.ToLower(selector), selector)
	}

	return nil, fmt.Errorf("no volume matches selector %q (by index, name, UUID or role)", selector)
}

// volumeByRole returns the single volume whose role matches token. selector is
// the caller's original spelling, used in error messages.
func volumeByRole(volumes []*Volume, token, selector string) (*Volume, error) {
	want, err := ParseVolumeRole(token)
	if err != nil {
		return nil, fmt.Errorf("invalid volume selector %q: %w", selector, err)
	}
	if want == VolumeRoleNone {
		return nil, fmt.Errorf("invalid volume selector %q: %q is not a role a volume can be selected by", selector, token)
	}

	var matches []*Volume
	var indices []int
	for index, volume := range volumes {
		if role, err := volume.Role(); err == nil && role == want {
			matches = append(matches, volume)
			indices = append(indices, index)
		}
	}

	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("no volume has the %q role", token)
	case 1:
		return matches[0], nil
	default:
		// A container can legally hold several volumes with the same role — two
		// recovery volumes in a multi-OS container, for instance. Name them
		// rather than choosing for the caller.
		var described []string
		for i, volume := range matches {
			name, _ := volume.UTF8Name()
			described = append(described, fmt.Sprintf("%d (%s)", indices[i], name))
		}
		return nil, fmt.Errorf("%d volumes have the %q role: %s; select one by index, name or UUID",
			len(matches), token, strings.Join(described, ", "))
	}
}

// applyPasswords sets the container's open-time passwords on a volume and
// attempts to unlock it. Unlock failures are left for the caller to surface
// when the volume is actually read.
func (c *Container) applyPasswords(volume *Volume) {
	if c.userPassword != "" {
		if err := volume.SetUTF8Password([]byte(c.userPassword)); err == nil {
			_, _ = volume.Unlock()
		}
	}
	if c.recoveryPassword != "" {
		if err := volume.SetUTF8RecoveryPassword([]byte(c.recoveryPassword)); err == nil {
			_, _ = volume.Unlock()
		}
	}
}

func formatVolumeUUID(uuid [16]byte) string {
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid[0], uuid[1], uuid[2], uuid[3],
		uuid[4], uuid[5],
		uuid[6], uuid[7],
		uuid[8], uuid[9],
		uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15])
}
