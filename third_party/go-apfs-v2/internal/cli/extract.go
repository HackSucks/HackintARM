// apfs extract IMAGE [PATH] — extract files to a local directory.
package cli

import (
	"fmt"
	"regexp"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/tools"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var (
	extractDestination    string
	extractPattern        string
	extractRecursive      bool
	extractPreserveMeta   bool
	extractXattrs         bool
	extractVerify         bool
	extractSymlinks       string
	extractMetadataRoot   string
	extractMetadataBudget int64
	extractProjectNative  bool
)

var extractCmd = &cobra.Command{
	Use:   "extract IMAGE [PATH]",
	Short: "Extract files from an APFS volume",
	Long: `Extract files from an APFS volume to a local directory. Without PATH
the whole volume is extracted.

Exit code 6 indicates a partial extraction: some entries were skipped and a
warning was printed to stderr for each.

--xattrs selects extended attributes for retention and requires --metadata-root.
--preserve-meta selects inode permissions, ownership, flags and timestamps and
also requires --metadata-root. Missing carrier selection fails before extraction.
Omitting --xattrs excludes attributes from the extraction.

--metadata-root selects a separate directory for portable metadata transport.
With it, selected --xattrs/--preserve-meta categories are retained with original
names and link relationships for repacking on Linux, macOS and Windows. The
payload destination must be empty. Supply the same metadata directory explicitly
to pack; arbitrary ._ files are always ordinary payload files.

--project-native also applies selected metadata to the working copy, and requires
--metadata-root. This can enforce restrictive permissions or ACLs. Native outcomes
are reported separately; the carrier retains metadata the host cannot represent.

Symlink handling (--symlinks): "auto" (default) creates a real symlink where
the OS allows it and otherwise writes the link target into a regular file
(useful on Windows without the symlink privilege); "real" always creates a
symlink and fails if the OS refuses; "file" always writes the target as a
regular file.

Examples:
  apfs extract image.dmg -C ./out
  apfs extract image.dmg /Applications/Some.app -C ./out --recursive
  apfs extract image.dmg -C ./out --pattern '\.plist$'
  apfs extract image.dmg -C ./out --xattrs --preserve-meta --metadata-root ./metadata --verify`,
	Args: rangeArgs(1, 2, "IMAGE [PATH]"),
	RunE: runExtract,
}

func init() {
	extractCmd.Flags().StringVarP(&extractDestination, "destination", "C", "", "destination directory (required)")
	extractCmd.Flags().StringVar(&extractPattern, "pattern", "", "only extract files whose path matches this regex")
	extractCmd.Flags().BoolVarP(&extractRecursive, "recursive", "r", false, "recurse into a directory PATH")
	extractCmd.Flags().BoolVar(&extractPreserveMeta, "preserve-meta", false, "retain inode metadata; requires --metadata-root")
	extractCmd.Flags().BoolVar(&extractXattrs, "xattrs", false, "retain extended attributes; requires --metadata-root")
	extractCmd.Flags().BoolVar(&extractVerify, "verify", false, "verify extracted files against source checksums")
	extractCmd.Flags().StringVar(&extractSymlinks, "symlinks", "auto", "symlink handling: auto, real or file")
	extractCmd.Flags().StringVar(&extractMetadataRoot, "metadata-root", "", "separate directory for portable metadata; required again when repacking")
	extractCmd.Flags().Int64Var(&extractMetadataBudget, "metadata-blob-limit", 1<<40, "maximum bytes per portable metadata blob")
	extractCmd.Flags().BoolVar(&extractProjectNative, "project-native", false, "also apply selected metadata to the host payload; requires --metadata-root")
	extractCmd.MarkFlagRequired("destination")
}

func runExtract(cmd *cobra.Command, args []string) error {
	if (extractXattrs || extractPreserveMeta) && extractMetadataRoot == "" {
		return usageErrorf("--xattrs and --preserve-meta require --metadata-root to preserve metadata on every filesystem; add --project-native to also apply it to the working copy")
	}
	if extractProjectNative && extractMetadataRoot == "" {
		return usageErrorf("--project-native requires --metadata-root")
	}
	imagePath := args[0]
	volumePath := "/"
	if len(args) == 2 {
		volumePath = args[1]
	}

	volume, closer, err := openFileSystem(imagePath)
	if err != nil {
		return err
	}
	defer closer.Close()

	var pattern *regexp.Regexp
	if extractPattern != "" {
		pattern, err = regexp.Compile(extractPattern)
		if err != nil {
			return usageErrorf("invalid --pattern: %v", err)
		}
	}

	var symlinkMode tools.SymlinkMode
	switch extractSymlinks {
	case "auto":
		symlinkMode = tools.SymlinkAuto
	case "real":
		symlinkMode = tools.SymlinkReal
	case "file":
		symlinkMode = tools.SymlinkFile
	default:
		return usageErrorf("invalid --symlinks %q: must be auto, real or file", extractSymlinks)
	}

	extractor := tools.NewExtractor(volume, extractDestination)
	extractor.Pattern = pattern
	extractor.PreserveMeta = extractPreserveMeta
	extractor.Xattrs = extractXattrs
	extractor.Verbose = opts.Verbose
	extractor.VerifyChecksum = extractVerify
	extractor.SymlinkMode = symlinkMode
	extractor.MetadataRoot = extractMetadataRoot
	extractor.ProjectNative = extractProjectNative
	extractor.Context = cmd.Context()
	limits := metatransport.DefaultLimits()
	limits.BlobBytes = extractMetadataBudget
	extractor.MetadataLimits = &limits

	if !opts.Verbose && !opts.Quiet && stderrIsTTY() {
		extractor.SetProgressBar(progressbar.NewOptions(-1,
			progressbar.OptionSetDescription("Extracting"),
			progressbar.OptionShowCount(),
			progressbar.OptionSetWidth(40),
			progressbar.OptionThrottle(100*time.Millisecond),
			progressbar.OptionSpinnerType(14),
			progressbar.OptionShowElapsedTimeOnFinish(),
			progressbar.OptionSetWriter(cmd.ErrOrStderr()),
		))
	}

	if volumePath != "" && volumePath != "/" {
		err = extractor.ExtractByPath(volumePath, extractRecursive)
	} else {
		err = extractor.ExtractAll()
	}
	if err != nil {
		return fmt.Errorf("extraction failed: %w", err)
	}

	extractor.FinishProgress()

	files, bytes := extractor.Stats()

	if opts.Output == "json" {
		summary := map[string]any{
			"destination":      extractDestination,
			"files":            files,
			"bytes":            bytes,
			"skipped":          extractor.Skipped(),
			"symlinksDegraded": extractor.SymlinksDegraded(),
			"namesRemapped":    extractor.NamesRemapped(),
		}
		if extractXattrs {
			restored, unwritable := extractor.XattrStats()
			summary["xattrsRestored"] = restored
			summary["xattrsUnwritable"] = unwritable
			summary["xattrsCarried"] = extractor.XattrsCarried()
		}
		if extractProjectNative {
			summary["nativeProjection"] = projectionJSON(extractor.NativeProjectionResults())
		}
		if err := jsonOut(summary); err != nil {
			return err
		}
	} else if !opts.Quiet {
		fmt.Printf("\nExtraction complete! Files saved to: %s\n", extractDestination)
		fmt.Printf("Total: %d files, %s\n", files, formatSize(bytes))
		if degraded := extractor.SymlinksDegraded(); degraded > 0 {
			fmt.Printf("Note: %d symlink(s) written as regular files (OS symlink support unavailable)\n", degraded)
		}
		if remapped := extractor.NamesRemapped(); remapped > 0 {
			fmt.Printf("Note: %d name(s) sanitized to be storable on this file system\n", remapped)
		}
		if extractXattrs {
			restored, unwritable := extractor.XattrStats()
			if extractProjectNative {
				fmt.Printf("%d native extended attribute write(s) succeeded\n", restored)
			}
			if carried := extractor.XattrsCarried(); carried > 0 {
				fmt.Printf("Preserved %d extended attribute(s) in %s\n", carried, extractMetadataRoot)
			}
			if unwritable > 0 {
				fmt.Printf("Note: %d extended attribute(s) could not be written to this file system\n", unwritable)
			}
		}
	}
	if extractProjectNative && opts.Output != "json" {
		for _, r := range extractor.NativeProjectionResults() {
			if r.Status != tools.ProjectionApplied || !r.Verified {
				fmt.Fprintf(cmd.ErrOrStderr(), "Native metadata %s %s: %s (verified=%t)", r.Path, r.Field, r.Status, r.Verified)
				if r.Err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), ": %v", r.Err)
				}
				fmt.Fprintln(cmd.ErrOrStderr())
			}
		}
	}

	if extractVerify {
		if !opts.Quiet {
			fmt.Println("\n=== Verifying Checksums ===")
		}
		if err := extractor.VerifyExtractedFiles(); err != nil {
			return withCode(ExitPartial, fmt.Errorf("verification failed: %w", err))
		}
	}

	if skipped := extractor.Skipped(); skipped > 0 {
		return withCode(ExitPartial, fmt.Errorf("partial extraction: %d entries could not be extracted (see warnings above)", skipped))
	}

	return nil
}

func projectionJSON(results []tools.ProjectionResult) []map[string]any {
	rows := make([]map[string]any, 0, len(results))
	for _, result := range results {
		row := map[string]any{"path": result.Path, "field": result.Field, "status": result.Status, "verified": result.Verified}
		if result.Err != nil {
			row["error"] = result.Err.Error()
		}
		rows = append(rows, row)
	}
	return rows
}
