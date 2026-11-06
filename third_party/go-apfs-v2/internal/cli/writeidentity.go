// Identity and timestamp flags shared by the commands that build a volume:
// create, pack and snapshot create. Together with --source-date-epoch (a root
// persistent flag, see root.go) they make output byte-identical for identical
// input, so a built image can be content-addressed and compared by hash.
package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

// writeIdentityFlags are the UUID flags one volume-building command accepts.
// Each command owns an instance; they are per-command flags, so unlike the root
// persistent flags they get no APFS_* environment or config-file binding.
type writeIdentityFlags struct {
	uuid          string
	volumeUUID    string
	containerUUID string
}

// register adds the identity flags to cmd. containerFlag is false for commands
// that never write an APFS container.
func (f *writeIdentityFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.uuid, "uuid", "",
		"volume UUID; for APFS the container UUID is derived from it (default: a fixed deterministic UUID)")
	cmd.Flags().StringVar(&f.volumeUUID, "volume-uuid", "",
		"volume UUID, overriding --uuid")
	cmd.Flags().StringVar(&f.containerUUID, "container-uuid", "",
		"APFS only: container UUID, overriding the value derived from --uuid")
}

// changed reports whether any identity flag was supplied.
func (f *writeIdentityFlags) changed() bool {
	return f.uuid != "" || f.volumeUUID != "" || f.containerUUID != ""
}

// resolve turns the flag trio into the container and volume UUIDs the APFS
// writer takes. A zero UUID means "use the writer's deterministic default", so
// an unset flag resolves to zero and an explicitly zero UUID is rejected.
func (f *writeIdentityFlags) resolve() (container, volume [16]byte, err error) {
	if f.volumeUUID != "" {
		volume, err = parseUUIDFlag("--volume-uuid", f.volumeUUID)
	} else if f.uuid != "" {
		volume, err = parseUUIDFlag("--uuid", f.uuid)
	}
	if err != nil {
		return container, volume, err
	}

	switch {
	case f.containerUUID != "":
		container, err = parseUUIDFlag("--container-uuid", f.containerUUID)
	case volume != ([16]byte{}):
		// A caller who pinned the volume UUID but not the container's would
		// otherwise silently get the hardcoded default container UUID, which is
		// surprising. Derive one from the volume UUID instead: deterministic,
		// and distinct from it.
		container = deriveContainerUUID(volume)
	}
	return container, volume, err
}

// resolveVolumeOnly resolves the volume UUID for a file system that has no
// container, rejecting --container-uuid as meaningless there.
func (f *writeIdentityFlags) resolveVolumeOnly(fsName string) ([16]byte, error) {
	if f.containerUUID != "" {
		return [16]byte{}, usageErrorf("--container-uuid does not apply to %s: it has no container", fsName)
	}
	_, volume, err := f.resolve()
	return volume, err
}

// parseUUIDFlag parses a UUID flag value into the fixed-size array the writers
// take. An all-zero UUID is rejected: the writers read zero as "use the
// deterministic default", so accepting it would silently ignore the flag.
func parseUUIDFlag(name, value string) ([16]byte, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	if err != nil {
		return [16]byte{}, usageErrorf("invalid %s %q: %v", name, value, err)
	}
	if parsed == uuid.Nil {
		return [16]byte{}, usageErrorf("invalid %s: the all-zero UUID selects the built-in default and cannot be requested explicitly", name)
	}
	return parsed, nil
}

// deriveContainerUUID returns the container UUID implied by a volume UUID: an
// RFC 4122 version 5 (SHA-1) UUID with the volume UUID as the namespace. It is
// deterministic and carries correct version and variant bits.
func deriveContainerUUID(volume [16]byte) [16]byte {
	return uuid.NewSHA1(uuid.UUID(volume), []byte("container"))
}

// writerTimes returns the FixedTime and clamp setting the file system writers
// should use for this invocation. With no --source-date-epoch the zero time is
// returned, letting each writer apply its own DefaultTime rather than having
// the CLI hardcode the constant twice.
func writerTimes() (fixed time.Time, clamp bool) {
	if opts.SourceDateEpoch.IsZero() {
		return time.Time{}, false
	}
	return opts.SourceDateEpoch, true
}

// parseSourceDateEpoch parses a SOURCE_DATE_EPOCH value: decimal seconds since
// 1970 UTC, per the reproducible-builds specification. Only that form is
// accepted so the flag and the environment variable can never disagree about
// what a value means.
func parseSourceDateEpoch(raw string) (time.Time, error) {
	var secs int64
	trimmed := strings.TrimSpace(raw)
	if _, err := fmt.Sscanf(trimmed, "%d", &secs); err != nil || secs < 0 || fmt.Sprint(secs) != trimmed {
		return time.Time{}, usageErrorf("invalid SOURCE_DATE_EPOCH %q: expected decimal seconds since 1970 UTC", raw)
	}
	return time.Unix(secs, 0).UTC(), nil
}
