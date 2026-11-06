// apfs mount IMAGE MOUNTPOINT — read-only FUSE mount.
package cli

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v2/internal/tools"
	"github.com/spf13/cobra"
)

var mountCmd = &cobra.Command{
	Use:   "mount IMAGE MOUNTPOINT",
	Short: "Mount an image read-only via FUSE (Linux and macOS)",
	Long: `Mount an APFS or HFS+ image read-only using FUSE. Available on Linux
and macOS (requires macFUSE); on other platforms this command exits with code 5.

The file system is detected automatically. Extended attributes are served for
volumes that carry them, so xattr and ls -l@ work against the mount.

Press Ctrl+C to unmount.

Examples:
  apfs mount image.dmg /mnt/image
  apfs mount -v 1 image.dmg /mnt/image
  apfs mount -p secret encrypted.dmg /mnt/image`,
	Args: exactArgs(2, "IMAGE MOUNTPOINT"),
	RunE: runMount,
}

func runMount(cmd *cobra.Command, args []string) error {
	imagePath := args[0]
	mountPoint := args[1]

	if stat, err := os.Stat(mountPoint); err != nil {
		return usageErrorf("mount point does not exist: %v", err)
	} else if !stat.IsDir() {
		return usageErrorf("mount point is not a directory")
	}

	// The opener list, cat and extract already share, so mount honours
	// --volume, --offset and the password flags identically -- and works for
	// every file system this tool reads rather than only APFS.
	volume, closer, err := openFileSystem(imagePath)
	if err != nil {
		return err
	}
	defer closer.Close()

	server, err := tools.MountVolumeFS(volume, "apfs", mountPoint, opts.Verbose)
	if err != nil {
		return withCode(ExitUnsupported, fmt.Errorf("unable to mount file system: %w", err))
	}

	if !opts.Quiet {
		fmt.Fprintf(os.Stderr, "Mounted at %s. Press Ctrl+C to unmount.\n", mountPoint)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	if !opts.Quiet {
		fmt.Fprintln(os.Stderr, "\nUnmounting...")
	}

	if err := server.Unmount(); err != nil {
		return fmt.Errorf("error during unmount: %w", err)
	}

	return nil
}
