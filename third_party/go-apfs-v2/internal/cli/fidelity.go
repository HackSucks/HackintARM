// Reporting for what a directory-to-volume write could not carry across, and
// the --strict gate that refuses to write a lossy image at all.
package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/fidelity"
)

// fidelityWarner returns a Warn callback for the writer walks. Warnings go to
// stderr as they are found, capped per kind: a tree with an extended attribute
// on every file would otherwise emit one line per file and bury the summary
// they exist to support.
//
// The cap is on output, not on counting — the totals in the summary and in the
// JSON are complete.
func fidelityWarner() func(string, fidelity.Kind, string) {
	shown := map[fidelity.Kind]int{}
	return func(path string, kind fidelity.Kind, detail string) {
		shown[kind]++
		switch {
		case shown[kind] <= fidelity.ExampleLimit:
			fmt.Fprintf(os.Stderr, "Note: %s: %s (%s)\n", path, kind.Lost(), detail)
		case shown[kind] == fidelity.ExampleLimit+1:
			fmt.Fprintf(os.Stderr, "Note: further %s notices suppressed; see the summary\n", kind)
		}
	}
}

// printFidelityNotes writes the summary block. It honours --quiet, unlike the
// per-entry warnings above: the individual notices are the record that
// something was lost, and suppressing those entirely would make a lossy write
// silent, which is the failure this whole mechanism exists to prevent.
func printFidelityNotes(report *fidelity.Report) {
	if opts.Quiet || report.Lossless() {
		return
	}
	for _, kind := range report.Kinds() {
		count := report.Count(kind)
		fmt.Printf("Note: %d %s%s %s\n", count, kind, plural(count), kind.Note())
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// enforceStrict fails the run when the walk lost anything and --strict is set.
//
// It is called after the walk and before anything is written, so a strict
// failure leaves no destination file behind. That ordering is the point of the
// flag: in a pipeline, a half-faithful image that exists is worse than no image.
func enforceStrict(report *fidelity.Report, strict bool, source string) error {
	if !strict || report.Lossless() {
		return nil
	}

	var parts []string
	for _, kind := range report.Kinds() {
		count := report.Count(kind)
		parts = append(parts, fmt.Sprintf("%d %s%s", count, kind, plural(count)))
	}
	return withCode(ExitUnsupported, fmt.Errorf(
		"--strict: %s contains %s that this volume cannot carry; nothing was written",
		source, strings.Join(parts, ", ")))
}

// fidelityExit returns the exit code a completed write should report.
//
// Entries omitted from the volume altogether are a partial result, the same
// meaning extract already gives exit 6. Metadata that could not be carried —
// extended attributes, BSD flags, a hard link written as a copy — is reported
// but does not change the exit code, because macOS attaches com.apple.provenance
// to files as they are written: treating a dropped attribute as failure would
// make almost every pack of a macOS tree exit non-zero and break existing
// scripts. --strict is how a caller asks for the stricter contract.
func fidelityExit(report *fidelity.Report) error {
	skipped := report.EntriesSkipped()
	if skipped == 0 {
		return nil
	}
	return withCode(ExitPartial, fmt.Errorf(
		"%d entr%s could not be written (see the notes above)",
		skipped, map[bool]string{true: "y", false: "ies"}[skipped == 1]))
}
