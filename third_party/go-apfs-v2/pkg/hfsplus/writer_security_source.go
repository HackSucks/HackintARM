package hfsplus

import (
	"github.com/deploymenttheory/go-apfs-v2/internal/imageacl"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// CopySecurityFrom validates the tree and acquires source metadata before
// staging ordinary security copying. ImageSecurityCapture connects APFS/HFS+
// readers directly. All callbacks must leave the destination tree untouched.
// Fatal capture errors stop before target ACL reads, volume queries or edits.
// Inspect Capture.Failures: native stat fallback can complete with unobserved
// ACL properties. Copy.Completed means staged; serialization must still succeed.
// This shared implementation supports Linux, macOS and Windows. Native host
// bindings and full restoration ordering are separate from image staging.
func (root *Entry) CopySecurityFrom(target *Entry, capture hostdata.SecuritySourceCapture, options hostdata.SecurityCopyOptions) (hostdata.SecuritySourceCopyResult, error) {
	return imageacl.CopyFrom(root, target, capture, options, (*Entry).imageSecurityNode, applySecurityCopy)
}
