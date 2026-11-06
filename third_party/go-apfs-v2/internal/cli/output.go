// Output helpers: JSON encoding to stdout, TTY detection, byte formatting.
package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/term"
)

// jsonOut writes one value as a JSON line to stdout.
func jsonOut(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	return encoder.Encode(value)
}

// stderrIsTTY reports whether stderr is an interactive terminal (progress
// bars are only shown when it is).
func stderrIsTTY() bool {
	return term.IsTerminal(int(os.Stderr.Fd()))
}

// stdoutIsTTY reports whether stdout is an interactive terminal (colors are
// only used when it is).
func stdoutIsTTY() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// formatNumber formats a number with comma separators.
func formatNumber(n uint64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var result []byte
	for i, digit := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, digit)
	}
	return string(result)
}

// formatBytes is an alias kept for the renderers ported from internal/tools.
func formatBytes(bytes uint64) string { return formatSize(bytes) }

// repeatChar repeats a character n times.
func repeatChar(char rune, n int) string {
	if n <= 0 {
		return ""
	}
	result := make([]rune, n)
	for i := range result {
		result[i] = char
	}
	return string(result)
}

// formatSize converts bytes to a human-readable string.
func formatSize(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	return fmt.Sprintf("%.1f %s", float64(bytes)/float64(div), units[exp])
}
