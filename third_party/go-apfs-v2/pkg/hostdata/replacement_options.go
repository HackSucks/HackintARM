package hostdata

import "github.com/deploymenttheory/go-apfs-v2/pkg/osversion"

// ReplacementOptions controls macOS compatibility of the portable filesystem
// metadata writer. Native filesystem metadata always uses the host's actual
// operations. These are SDK options, not codesign command-line flags.
type ReplacementOptions struct {
	// MacOSProfile selects the qualified FAT/exFAT attribute-file behavior on
	// Linux and Windows. Zero selects macOS 27. macOS uses its native VFS.
	MacOSProfile osversion.MacOSProfile
}

func (options ReplacementOptions) filesystemProfile() (osversion.MacOSProfile, error) {
	if options.MacOSProfile == 0 {
		return osversion.MacOS27, nil
	}
	switch options.MacOSProfile {
	case osversion.MacOS15, osversion.MacOS26, osversion.MacOS27:
		return options.MacOSProfile, nil
	default:
		return 0, osversion.ErrMacOSProfile
	}
}
