// Package exitcode defines the exit-code contract of the apfs command.
//
// These values are stable: scripts, pipelines and the acceptance suite depend
// on them, so a code's meaning must not change once released. Add new codes
// rather than repurposing existing ones.
package exitcode

// Exit codes returned by the apfs command.
const (
	// OK indicates the operation completed successfully.
	OK = 0
	// Error indicates a generic runtime error.
	Error = 1
	// Usage indicates bad flags or arguments.
	Usage = 2
	// BadImage indicates the image was not found, or is not a recognizable
	// APFS or HFS+ image.
	BadImage = 3
	// Auth indicates authentication was required and was not supplied, or
	// failed.
	Auth = 4
	// Unsupported indicates the requested feature is not supported on this
	// platform or for this image.
	Unsupported = 5
	// Partial indicates the operation completed partially — for example an
	// extraction in which some files were skipped.
	Partial = 6
)

// Name returns a short human-readable name for an exit code, for use in test
// failures and diagnostics. Unknown codes are rendered as their number.
func Name(code int) string {
	switch code {
	case OK:
		return "OK"
	case Error:
		return "Error"
	case Usage:
		return "Usage"
	case BadImage:
		return "BadImage"
	case Auth:
		return "Auth"
	case Unsupported:
		return "Unsupported"
	case Partial:
		return "Partial"
	default:
		return "Unknown"
	}
}
