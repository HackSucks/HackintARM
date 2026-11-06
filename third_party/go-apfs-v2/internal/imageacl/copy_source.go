package imageacl

import "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"

// CopyFrom validates the destination graph, acquires a source, then stages the
// same copy and alias publication as Copy. Fatal source failures cannot publish edits.
func CopyFrom[T comparable](root, target T, capture hostdata.SecuritySourceCapture, options hostdata.SecurityCopyOptions, read func(T, bool) (Node[T], error), write func(T, Change)) (result hostdata.SecuritySourceCopyResult, err error) {
	if !options.ACL && !options.Stat {
		return hostdata.CopySecurityFrom(capture, options, nil)
	}
	_, err = stageCopy(root, target, read, write, func(backend *copier) (hostdata.SecurityCopyResult, error) {
		var runErr error
		result, runErr = hostdata.CopySecurityFrom(capture, options, backend)
		return result.Copy, runErr
	})
	return result, err
}
