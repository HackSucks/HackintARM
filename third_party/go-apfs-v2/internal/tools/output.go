// Output utilities for APFS tools
package tools

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
)

const (
	LibraryName = "go-apfs-v2"

	// Copyright information
	CopyrightYear   = "2026"
	CopyrightHolder = "Deployment Theory"
)

// version is stamped in by the linker on a release build, so the binary names
// the tag it was cut from. It is deliberately the only place a version is
// written down: it used to be a constant here and another in the command
// package, each with a comment asking whoever changed one to remember the
// other.
var version = "dev"

// fallbackVersion is reported when neither the linker nor the module system
// says anything, which means a plain "go build" from a source tree.
const fallbackVersion = "0.2.0"

// Version returns the version to report.
func Version() string {
	if version != "dev" {
		return version
	}
	// go install stamps the module version into the build info, so a binary
	// installed from a tag reports that tag without the linker being involved.
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return strings.TrimPrefix(v, "v")
		}
	}
	return fallbackVersion
}

// PrintCopyright prints copyright information to the specified writer
func PrintCopyright(w io.Writer) {
	if w == nil {
		w = os.Stderr
	}
	fmt.Fprintf(w, "Copyright (C) %s, %s.\n", CopyrightYear, CopyrightHolder)
	fmt.Fprintf(w, "This is free software; see the source for copying conditions. There is NO\n")
	fmt.Fprintf(w, "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n")
}

// PrintVersion prints version information to the specified writer
func PrintVersion(w io.Writer, programName string) {
	if w == nil {
		w = os.Stdout
	}
	fmt.Fprintf(w, "%s %s\n\n", programName, Version())
}

// PrintDetailedVersion prints detailed version information including library versions
func PrintDetailedVersion(w io.Writer, programName string) {
	if w == nil {
		w = os.Stdout
	}
	fmt.Fprintf(w, "%s %s (lib%s %s)\n\n", programName, Version(), LibraryName, Version())
	fmt.Fprintf(w, "Built with:\n")
	fmt.Fprintf(w, "  Go runtime\n")
	fmt.Fprintf(w, "  Native crypto support\n")
	fmt.Fprintf(w, "\n")
}

// PrintVersionAndCopyright prints both version and copyright information
func PrintVersionAndCopyright(w io.Writer, programName string) {
	PrintVersion(w, programName)
	PrintCopyright(w)
	fmt.Fprintln(w)
}

// SetBuffering sets the buffering mode for stdout and stderr
// In Go, this is generally handled automatically, but we provide this for API compatibility
func SetBuffering(mode int) error {
	// In Go, buffering is handled by the os package and bufio
	// This function exists mainly for API compatibility with the C version
	// The actual buffering behavior is controlled by the Go runtime
	return nil
}

// PrintError prints an error message to stderr
func PrintError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
}

// PrintWarning prints a warning message to stderr
func PrintWarning(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "WARNING: "+format+"\n", args...)
}

// PrintInfo prints an info message to stdout
func PrintInfo(format string, args ...interface{}) {
	fmt.Fprintf(os.Stdout, format+"\n", args...)
}

// PrintVerbose prints a verbose message if verbose mode is enabled
func PrintVerbose(verbose bool, format string, args ...interface{}) {
	if verbose {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
}

// PrintDebug prints a debug message if debug mode is enabled
func PrintDebug(debug bool, format string, args ...interface{}) {
	if debug {
		fmt.Fprintf(os.Stderr, "DEBUG: "+format+"\n", args...)
	}
}
