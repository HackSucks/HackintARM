// Extract tool for extracting files from APFS volumes
// Walks the volume through its io/fs view (pkg/apfs fs.go), so extraction
// exercises the same public API that SDK consumers use.
package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
	"github.com/schollz/progressbar/v3"
)

// VolumeFS is the file system contract the extractor walks. APFS and HFS+
// volumes both implement it.
type VolumeFS interface {
	fs.FS
	fs.ReadDirFS
	fs.StatFS
	fs.ReadFileFS
	Readlink(name string) (string, error)
}

// XattrVolume is implemented by volumes that can report a file's extended
// attributes. It is separate from VolumeFS because not every file system this
// tool reads has them, and extraction must work without.
type XattrVolume interface {
	Xattrs(name string) (map[string][]byte, error)
}

// XattrsCarried counts attributes safely published in the explicit carrier.
// This is separate from attributes actually applied by the host kernel.
func (e *Extractor) XattrsCarried() int { return e.xattrsCarried }

// SymlinkMode controls how symbolic links are materialized on disk.
type SymlinkMode int

const (
	// SymlinkAuto creates a real symlink where the OS permits it and falls
	// back to a regular file containing the target path otherwise (as git
	// does with core.symlinks=false). This never fails on symlink support.
	SymlinkAuto SymlinkMode = iota
	// SymlinkReal always creates a real symlink and reports a failure if the
	// OS refuses (e.g. unprivileged Windows).
	SymlinkReal
	// SymlinkFile always writes the target path into a regular file.
	SymlinkFile
)

// Extractor handles file extraction from APFS volumes
type Extractor struct {
	// MetadataRoot explicitly selects a separate portable carrier directory.
	// Selected categories survive independently of host metadata support.
	// ProjectNative explicitly also attempts native enforcement/materialization.
	// It requires MetadataRoot and may restrict subsequent payload access.
	ProjectNative       bool
	projectionResults   []ProjectionResult
	MetadataRoot        string
	MetadataLimits      *metatransport.Limits
	NativeCaptureLimits *hostdata.XattrCaptureLimits
	Context             context.Context
	Volume              VolumeFS
	Destination         string
	Pattern             *regexp.Regexp
	PreserveMeta        bool
	Verbose             bool
	VerifyChecksum      bool
	// Xattrs retains complete extended attributes in MetadataRoot. Native
	// materialization additionally requires ProjectNative; a native store's
	// constraints cannot discard values selected for preservation.
	Xattrs           bool
	SymlinkMode      SymlinkMode
	filesExtracted   int
	xattrsRestored   int
	xattrsUnwritable int
	xattrsCarried    int
	entriesSkipped   int
	symlinksDegraded int
	namesRemapped    int
	bytesExtracted   uint64
	sourceChecksums  map[string]string // relativePath -> SHA256 of source data
	progressBar      *progressbar.ProgressBar
}

// warnSkip reports an entry that could not be extracted. Warnings always go
// to stderr so partial extractions are never silent, and the skip count makes
// the run exit non-zero.
func (e *Extractor) warnSkip(format string, args ...any) {
	e.entriesSkipped++
	fmt.Fprintf(os.Stderr, "Warning: "+format+"\n", args...)
}

// destPath joins rel under the destination root, sanitizing each path
// component so it is representable on the host OS (e.g. Windows rejects
// trailing spaces/dots, reserved characters and reserved device names). When
// a component is remapped the change is reported and counted, so extraction
// stays lossless in content and never fails purely because the source used a
// name the destination file system cannot store verbatim.
func (e *Extractor) destPath(rel string) string {
	if rel == "" {
		return e.Destination
	}
	sanitized, changed := sanitizePathForHost(rel)
	if changed {
		e.namesRemapped++
		fmt.Fprintf(os.Stderr, "Note: %q cannot be represented on this file system; extracted as %q\n", rel, sanitized)
	}
	return filepath.Join(e.Destination, filepath.FromSlash(sanitized))
}

// ExtractAll extracts the entire volume into the destination directory.
func (e *Extractor) ExtractAll() error {
	if (e.Xattrs || e.PreserveMeta) && e.MetadataRoot == "" {
		return errors.New("metadata preservation requires a metadata root")
	}
	if e.ProjectNative && e.MetadataRoot == "" {
		return errors.New("native projection requires a metadata root")
	}
	if e.MetadataRoot != "" {
		return e.extractCarrier(".", "")
	}
	return e.extractTree(".", "")
}

// ExtractByPath extracts a specific file or directory by absolute volume path.
func (e *Extractor) ExtractByPath(volumePath string, recursive bool) error {
	if (e.Xattrs || e.PreserveMeta) && e.MetadataRoot == "" {
		return errors.New("metadata preservation requires a metadata root")
	}
	if e.ProjectNative && e.MetadataRoot == "" {
		return errors.New("native projection requires a metadata root")
	}
	name := FSNameFromVolumePath(volumePath)

	info, err := e.Volume.Stat(name)
	if err != nil {
		return fmt.Errorf("unable to find path %s: %w", volumePath, err)
	}

	base := path.Base(name)
	if e.MetadataRoot != "" {
		if info.IsDir() && !recursive {
			return fmt.Errorf("%s is a directory; use --recursive to extract its contents", volumePath)
		}
		return e.extractCarrier(name, base)
	}

	if info.IsDir() {
		if !recursive {
			return fmt.Errorf("%s is a directory; use --recursive to extract its contents", volumePath)
		}
		return e.extractTree(name, base)
	}

	if info.Mode()&fs.ModeSymlink != 0 {
		return e.extractSymlink(name, e.destPath(base))
	}

	return e.extractFile(name, e.destPath(base), info)
}

// extractTree walks the subtree rooted at root (an fs.FS name) and recreates
// it under Destination/destBase. Individual failures are reported and counted
// but do not abort the walk.
func (e *Extractor) extractTree(root, destBase string) error {
	type pendingDir struct {
		destPath string
		info     fs.FileInfo
	}
	var dirs []pendingDir

	err := fs.WalkDir(e.Volume, root, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if name == root {
				return walkErr
			}
			e.warnSkip("unable to walk %s: %v", name, walkErr)
			return nil
		}

		// Destination path: name relative to the walk root, under destBase
		rel := strings.TrimPrefix(strings.TrimPrefix(name, root), "/")
		if root == "." {
			rel = name
			if rel == "." {
				rel = ""
			}
		}
		destRel := rel
		if destBase != "" {
			destRel = path.Join(destBase, rel)
		}
		destPath := e.destPath(destRel)

		switch {
		case entry.IsDir():
			if err := os.MkdirAll(destPath, 0755); err != nil {
				e.warnSkip("unable to create directory %s: %v", destPath, err)
				return fs.SkipDir
			}
			if e.Verbose {
				fmt.Printf("Created directory: %s\n", destPath)
			}
			if e.PreserveMeta {
				if info, err := entry.Info(); err == nil {
					// Applied after the walk so extracting children does not
					// bump the directory's restored timestamps
					dirs = append(dirs, pendingDir{destPath: destPath, info: info})
				}
			}

		case entry.Type()&fs.ModeSymlink != 0:
			if err := e.extractSymlink(name, destPath); err != nil {
				e.warnSkip("unable to extract symlink %s: %v", name, err)
			}

		case entry.Type().IsRegular():
			if e.Pattern != nil && !e.Pattern.MatchString(rel) {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				e.warnSkip("unable to stat %s: %v", name, err)
				return nil
			}
			if err := e.extractFile(name, destPath, info); err != nil {
				e.warnSkip("unable to extract %s: %v", name, err)
			}

		default:
			// Sockets, pipes, devices: nothing meaningful to extract
			if e.Verbose {
				fmt.Printf("Skipping special file: %s (%s)\n", name, entry.Type())
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Restore directory metadata deepest-first
	for i := len(dirs) - 1; i >= 0; i-- {
		e.applyMetadata(dirs[i].destPath, dirs[i].info)
	}

	return nil
}

// extractSymlink recreates the symlink at the fs name as destPath, applying
// the configured SymlinkMode. In auto mode, if the OS refuses to create a
// real symlink (e.g. unprivileged Windows), the target path is written into
// a regular file instead so no information is lost and extraction completes.
func (e *Extractor) extractSymlink(name, destPath string) error {
	target, err := e.Volume.Readlink(name)
	if err != nil {
		return fmt.Errorf("unable to read symlink target: %w", err)
	}

	switch e.SymlinkMode {
	case SymlinkFile:
		return e.writeSymlinkAsFile(destPath, target, nil)

	case SymlinkReal:
		if err := os.Symlink(target, destPath); err != nil {
			return err
		}

	default: // SymlinkAuto
		if err := os.Symlink(target, destPath); err != nil {
			// The symlink was read fine; the OS just won't materialize it.
			// Preserve it losslessly as a regular file (git-style fallback).
			return e.writeSymlinkAsFile(destPath, target, err)
		}
	}

	if e.Verbose {
		fmt.Printf("Created symlink: %s -> %s\n", destPath, target)
	} else if e.progressBar != nil {
		e.progressBar.Add(1)
	}
	e.filesExtracted++

	return nil
}

// writeSymlinkAsFile writes a symlink's target path into a regular file at
// destPath. cause is the original os.Symlink error when this is a fallback
// (nil when SymlinkFile mode was requested explicitly).
func (e *Extractor) writeSymlinkAsFile(destPath, target string, cause error) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("unable to create parent directory: %w", err)
	}
	if err := os.WriteFile(destPath, []byte(target), 0644); err != nil {
		return err
	}

	if cause != nil {
		e.symlinksDegraded++
		fmt.Fprintf(os.Stderr, "Note: %s could not be created as a symlink (%v); wrote its target %q as a regular file instead\n",
			destPath, cause, target)
	} else if e.Verbose {
		fmt.Printf("Wrote symlink target as file: %s -> %s\n", destPath, target)
	}
	if e.progressBar != nil {
		e.progressBar.Add(1)
	}
	e.filesExtracted++

	return nil
}

// extractFile copies the regular file at the fs name to destPath.
func (e *Extractor) extractFile(name, destPath string, info fs.FileInfo) error {
	source, err := e.Volume.Open(name)
	if err != nil {
		return err
	}
	defer source.Close()

	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("unable to create parent directory: %w", err)
	}

	outFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("unable to create file: %w", err)
	}
	defer outFile.Close()

	var reader io.Reader = source
	var sourceHasher = sha256.New()
	if e.VerifyChecksum {
		reader = io.TeeReader(source, sourceHasher)
	}

	written, err := io.Copy(outFile, reader)
	if err != nil {
		outFile.Close()
		os.Remove(destPath)
		return fmt.Errorf("unable to copy file data: %w", err)
	}

	if e.VerifyChecksum {
		relPath, err := filepath.Rel(e.Destination, destPath)
		if err == nil {
			e.sourceChecksums[relPath] = hex.EncodeToString(sourceHasher.Sum(nil))
		}
	}

	e.filesExtracted++
	e.bytesExtracted += uint64(written)

	if e.Verbose {
		fmt.Printf("  [%d] %s (%s)\n", e.filesExtracted, filepath.Base(destPath), formatBytes(uint64(written)))
	} else if e.progressBar != nil {
		e.progressBar.Add(1)
	}

	if e.PreserveMeta {
		e.applyMetadata(destPath, info)
	}
	if e.Xattrs {
		e.applyXattrs(name, destPath)
	}

	return nil
}

// applyXattrs copies the source entry's extended attributes onto the extracted
// file. An attribute that will not write is counted and reported rather than
// failing the extraction: some are reserved to the kernel, and some
// destination file systems take none at all.
func (e *Extractor) applyXattrs(name, destPath string) {
	source, ok := e.Volume.(XattrVolume)
	if !ok {
		return
	}
	attrs, err := source.Xattrs(name)
	if err != nil || len(attrs) == 0 {
		return
	}
	attrs = withoutCompressionMetadata(attrs)
	if len(attrs) == 0 {
		return
	}

	written, failed := hostdata.SetXattrs(destPath, attrs)
	e.xattrsRestored += written
	e.xattrsUnwritable += len(failed)
	if len(failed) > 0 && e.Verbose {
		fmt.Fprintf(os.Stderr, "Note: %s: %d extended attribute(s) could not be written: %s\n",
			destPath, len(failed), strings.Join(failed, ", "))
	}
}

// withoutCompressionMetadata drops the attributes that describe transparent
// compression, returning the rest.
//
// Extraction decompresses as it reads, so the extracted file holds its content
// in the data fork. Restoring com.apple.decmpfs alongside that would leave the
// file carrying metadata saying its content lives compressed in a resource fork
// that no longer describes it — a contradiction, and one that would render the
// file unreadable if anything later set UF_COMPRESSED. The resource fork goes
// with it, because for a compressed file that fork *is* the compressed copy.
//
// A resource fork without decmpfs is a genuine one and is restored.
func withoutCompressionMetadata(attrs map[string][]byte) map[string][]byte {
	if _, compressed := attrs[hostdata.DecmpfsName]; !compressed {
		return attrs
	}
	kept := make(map[string][]byte, len(attrs))
	for name, value := range attrs {
		if name == hostdata.DecmpfsName || name == hostdata.ResourceForkName {
			continue
		}
		kept[name] = value
	}
	return kept
}

// applyMetadata restores permissions and timestamps from the volume entry.
func (e *Extractor) applyMetadata(destPath string, info fs.FileInfo) {
	if err := os.Chmod(destPath, info.Mode().Perm()); err != nil && e.Verbose {
		fmt.Printf("Warning: unable to set permissions on %s: %v\n", destPath, err)
	}

	modTime := info.ModTime()
	accessTime := modTime
	if inode, ok := info.Sys().(*apfs.Inode); ok && inode.AccessTime != 0 {
		accessTime = time.Unix(0, int64(inode.AccessTime))
	}

	if err := os.Chtimes(destPath, accessTime, modTime); err != nil && e.Verbose {
		fmt.Printf("Warning: unable to set timestamps on %s: %v\n", destPath, err)
	}
}

// FSNameFromVolumePath converts an absolute volume path ("/a/b") to an fs.FS
// name ("a/b", or "." for the root).
func FSNameFromVolumePath(volumePath string) string {
	name := strings.Trim(path.Clean("/"+volumePath), "/")
	if name == "" {
		return "."
	}
	return name
}

// NewExtractor creates an extractor for a volume writing into destination.
func NewExtractor(volume VolumeFS, destination string) *Extractor {
	return &Extractor{
		Volume:          volume,
		Destination:     destination,
		sourceChecksums: make(map[string]string),
	}
}

// SetProgressBar attaches a progress bar (optional).
func (e *Extractor) SetProgressBar(bar *progressbar.ProgressBar) {
	e.progressBar = bar
}

// FinishProgress completes the progress bar if one is attached.
func (e *Extractor) FinishProgress() {
	if e.progressBar != nil {
		e.progressBar.Finish()
	}
}

// Skipped returns the number of entries that could not be extracted.
func (e *Extractor) Skipped() int {
	return e.entriesSkipped
}

// SymlinksDegraded returns the number of symlinks written as regular files
// because the OS would not create a real symlink.
func (e *Extractor) SymlinksDegraded() int {
	return e.symlinksDegraded
}

// NamesRemapped returns the number of entries whose names were sanitized to
// be storable on the host file system.
func (e *Extractor) NamesRemapped() int {
	return e.namesRemapped
}

// XattrStats returns successful native attribute writes and attributes that
// could not be projected. Successful writes include native normalization;
// NativeProjectionResults records whether readback matched the logical value.
// Carrier-only preservation is counted separately by XattrsCarried.
func (e *Extractor) XattrStats() (restored, unwritable int) {
	restored, unwritable = e.xattrsRestored, e.xattrsUnwritable
	for _, result := range e.projectionResults {
		if !strings.HasPrefix(result.Field, "xattr:") {
			continue
		}
		switch result.Status {
		case ProjectionApplied, ProjectionNormalized:
			restored++
		case ProjectionRetained, ProjectionFailed:
			unwritable++
		}
	}
	return restored, unwritable
}

// Stats returns extraction statistics
func (e *Extractor) Stats() (filesExtracted int, bytesExtracted uint64) {
	return e.filesExtracted, e.bytesExtracted
}

// VerifyExtractedFiles verifies that extracted files match source by comparing checksums
func (e *Extractor) VerifyExtractedFiles() error {
	if len(e.sourceChecksums) == 0 {
		fmt.Println("No checksums computed during extraction")
		return nil
	}

	headerText := fmt.Sprintf("Checksum Verification: %d files", len(e.sourceChecksums))
	boxWidth := len(headerText)
	fmt.Printf("╭─%s─╮\n", strings.Repeat("─", boxWidth))
	fmt.Printf("│ %-*s │\n", boxWidth, headerText)
	fmt.Printf("╰─%s─╯\n\n", strings.Repeat("─", boxWidth))

	verified := 0
	mismatches := 0
	missing := 0

	// Sort file paths for consistent output
	var sortedPaths []string
	for relPath := range e.sourceChecksums {
		sortedPaths = append(sortedPaths, relPath)
	}
	sort.Strings(sortedPaths)

	for _, relPath := range sortedPaths {
		sourceChecksum := e.sourceChecksums[relPath]
		destPath := filepath.Join(e.Destination, relPath)

		// Get file info
		fileInfo, err := os.Stat(destPath)
		if os.IsNotExist(err) {
			fmt.Printf("  ✗ MISSING\n")
			fmt.Printf("    %-20s  %s\n", "File", relPath)
			fmt.Printf("    %-20s  %s\n\n", "APFS checksum", sourceChecksum)
			missing++
			continue
		}

		// Compute checksum of extracted file
		extractedChecksum, err := computeFileChecksum(destPath)
		if err != nil {
			fmt.Printf("  ✗ ERROR\n")
			fmt.Printf("    %-20s  %s\n", "File", relPath)
			fmt.Printf("    %-20s  %v\n\n", "Error", err)
			continue
		}

		// Compare checksums
		match := sourceChecksum == extractedChecksum
		status := "✓"
		if !match {
			status = "✗"
			mismatches++
		} else {
			verified++
		}

		// Show file with both checksums for comparison
		fmt.Printf("  %s %s\n", status, relPath)
		fmt.Printf("      %-20s  %s\n", "Size", formatBytes(uint64(fileInfo.Size())))
		fmt.Printf("      %-20s  %s\n", "APFS SHA-256", sourceChecksum)
		fmt.Printf("      %-20s  %s\n", "Disk SHA-256", extractedChecksum)
		if !match {
			fmt.Printf("      %-20s  CHECKSUM MISMATCH!\n", "Status")
		}
		fmt.Println()
	}

	// Summary section
	fmt.Printf("\n╭─ Verification Summary ─────────────────────────────╮\n")
	fmt.Printf("│  %-30s  %19d │\n", "Total files verified", verified)
	if mismatches > 0 {
		fmt.Printf("│  %-30s  %19d │\n", "✗ Checksum mismatches", mismatches)
	}
	if missing > 0 {
		fmt.Printf("│  %-30s  %19d │\n", "✗ Missing files", missing)
	}
	fmt.Printf("╰────────────────────────────────────────────────────╯\n")

	if mismatches == 0 && missing == 0 {
		fmt.Println("\n✓ All files verified successfully!")
		return nil
	}

	return fmt.Errorf("verification failed: %d mismatches, %d missing", mismatches, missing)
}

// computeFileChecksum computes SHA-256 checksum of a file
func computeFileChecksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}
