// apfs list IMAGE [PATH] — directory listing.
package cli

import (
	"fmt"
	"io/fs"
	"path"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/tools"
	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/spf13/cobra"
)

var (
	listLong      bool
	listRecursive bool
)

var listCmd = &cobra.Command{
	Use:   "list IMAGE [PATH]",
	Short: "List directory contents",
	Long: `List the contents of a directory in an APFS volume (default: the
volume root).

With --output json, one JSON object is emitted per line for each entry, for
streaming consumption (jq, etc.).

Examples:
  apfs list image.dmg
  apfs list image.dmg /Applications --long
  apfs list -R image.dmg | wc -l
  apfs list -o json image.dmg / | jq -r 'select(.type=="file") | .path'`,
	Args: rangeArgs(1, 2, "IMAGE [PATH]"),
	RunE: runList,
}

func init() {
	listCmd.Flags().BoolVarP(&listLong, "long", "l", false, "long listing format")
	listCmd.Flags().BoolVarP(&listRecursive, "recursive", "R", false, "list subdirectories recursively")
}

// listEntry is the JSON schema for one listed entry.
type listEntry struct {
	Path    string    `json:"path"`
	Name    string    `json:"name"`
	Type    string    `json:"type"`
	Size    int64     `json:"size"`
	Mode    string    `json:"mode"`
	ModTime time.Time `json:"modTime"`
	Inode   uint64    `json:"inode,omitempty"`
	Target  string    `json:"target,omitempty"`
}

func runList(cmd *cobra.Command, args []string) error {
	imagePath := args[0]
	startPath := "/"
	if len(args) == 2 {
		startPath = args[1]
	}

	volume, closer, err := openFileSystem(imagePath)
	if err != nil {
		return err
	}
	defer closer.Close()

	name := tools.FSNameFromVolumePath(startPath)

	info, err := volume.Stat(name)
	if err != nil {
		return fmt.Errorf("unable to access %s: %w", startPath, err)
	}

	// Listing a non-directory shows the entry itself
	if !info.IsDir() {
		return emitEntry(volume, name, info)
	}

	if listRecursive {
		root := name
		return fs.WalkDir(volume, root, func(entryName string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entryName == root {
				return nil
			}
			entryInfo, err := entry.Info()
			if err != nil {
				return err
			}
			return emitEntry(volume, entryName, entryInfo)
		})
	}

	entries, err := volume.ReadDir(name)
	if err != nil {
		return fmt.Errorf("unable to list %s: %w", startPath, err)
	}

	for _, entry := range entries {
		entryInfo, err := entry.Info()
		if err != nil {
			return err
		}
		entryName := entry.Name()
		if name != "." {
			entryName = name + "/" + entryName
		}
		if err := emitEntry(volume, entryName, entryInfo); err != nil {
			return err
		}
	}

	return nil
}

// emitEntry prints one entry in the selected output format.
func emitEntry(volume volumeFS, name string, info fs.FileInfo) error {
	entryType := typeString(info.Mode())

	if opts.Output == "json" {
		entry := listEntry{
			Path:    name,
			Name:    path.Base(name),
			Type:    entryType,
			Size:    info.Size(),
			Mode:    info.Mode().String(),
			ModTime: info.ModTime().UTC(),
		}
		if inode, ok := info.Sys().(*apfs.Inode); ok {
			entry.Inode = inode.Identifier
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			if target, err := volume.Readlink(name); err == nil {
				entry.Target = target
			}
		}
		return jsonOut(entry)
	}

	displayName := name
	if info.Mode()&fs.ModeSymlink != 0 {
		if target, err := volume.Readlink(name); err == nil {
			displayName = name + " -> " + target
		}
	}

	if listLong {
		fmt.Printf("%-11s %10d %s %s\n",
			info.Mode().String(),
			info.Size(),
			info.ModTime().UTC().Format("2006-01-02 15:04:05"),
			colorizeName(displayName, info.Mode()))
		return nil
	}

	fmt.Println(colorizeName(displayName, info.Mode()))
	return nil
}

func typeString(mode fs.FileMode) string {
	switch {
	case mode.IsDir():
		return "dir"
	case mode&fs.ModeSymlink != 0:
		return "symlink"
	case mode&fs.ModeDevice != 0:
		return "device"
	case mode&fs.ModeNamedPipe != 0:
		return "pipe"
	case mode&fs.ModeSocket != 0:
		return "socket"
	default:
		return "file"
	}
}

// colorizeName colors directories and symlinks when stdout is a terminal.
func colorizeName(name string, mode fs.FileMode) string {
	if !stdoutIsTTY() {
		return name
	}
	switch {
	case mode.IsDir():
		return "\033[1;34m" + name + "\033[0m"
	case mode&fs.ModeSymlink != 0:
		return "\033[36m" + name + "\033[0m"
	case mode&0o111 != 0 && mode.IsRegular():
		return "\033[32m" + name + "\033[0m"
	default:
		return name
	}
}
