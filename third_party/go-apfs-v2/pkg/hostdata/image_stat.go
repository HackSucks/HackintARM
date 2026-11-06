package hostdata

// ImageStatCopyResult separates executor diagnostics from publication into an
// offline writer tree. Applied is true only when every staged operation succeeded
// and all aliases were updated. Execution.Completed alone is not publication.
// Serialization can still fail; the caller must check CreateContainer/CreateImage.
type ImageStatCopyResult struct {
	Execution StatCopyResult
	Applied   bool
}
