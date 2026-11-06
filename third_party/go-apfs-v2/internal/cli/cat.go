// apfs cat IMAGE PATH... — stream file contents to stdout.
package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/internal/tools"
	"github.com/spf13/cobra"
)

var catCmd = &cobra.Command{
	Use:   "cat IMAGE PATH...",
	Short: "Write file contents to standard output",
	Long: `Write the contents of one or more files from an APFS volume to
standard output, for use in pipelines.

Examples:
  apfs cat image.dmg /etc/hosts
  apfs cat image.dmg /app/Info.plist | plutil -p -`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
			return usageErrorf("expected IMAGE PATH... (got %d arguments)", len(args))
		}
		return nil
	},
	RunE: runCat,
}

func runCat(cmd *cobra.Command, args []string) error {
	imagePath := args[0]

	volume, closer, err := openFileSystem(imagePath)
	if err != nil {
		return err
	}
	defer closer.Close()

	for _, volumePath := range args[1:] {
		name := tools.FSNameFromVolumePath(volumePath)

		file, err := volume.Open(name)
		if err != nil {
			return fmt.Errorf("unable to open %s: %w", volumePath, err)
		}

		if info, err := file.Stat(); err == nil && info.IsDir() {
			file.Close()
			return usageErrorf("%s is a directory", volumePath)
		}

		if _, err := io.Copy(os.Stdout, file); err != nil {
			file.Close()
			return fmt.Errorf("unable to read %s: %w", volumePath, err)
		}
		file.Close()
	}

	return nil
}
