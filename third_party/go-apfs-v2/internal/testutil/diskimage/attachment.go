package diskimage

import (
	"fmt"
	"io/fs"
	"regexp"

	"howett.net/plist"
)

var wholeDevice = regexp.MustCompile(`^/dev/disk[0-9]+$`)

// AttachmentDevice returns the first whole device in hdiutil attach -plist's
// ordered system entities. This is the backing image device, preceding slices
// and any synthesized APFS container. Keep it for ordinary detach retries:
// a busy detach may unmount volumes before failing to eject their device.
// Never reconstruct an eject target from a subsequently missing mount path.
func AttachmentDevice(data []byte) (string, error) {
	var result struct {
		Entities []struct {
			Device string `plist:"dev-entry"`
		} `plist:"system-entities"`
	}
	if _, err := plist.Unmarshal(data, &result); err != nil {
		return "", fmt.Errorf("decode attached image: %w", err)
	}
	for _, entry := range result.Entities {
		if wholeDevice.MatchString(entry.Device) {
			return entry.Device, nil
		}
	}
	return "", fmt.Errorf("attached image has no whole device: %w", fs.ErrInvalid)
}
