package hostdata

import "io/fs"

// ImageSecurityReader is implemented by APFS/HFS+ volumes. The image must remain
// immutable across lookup/capture/copy. Native host account state is not used.
type ImageSecurityReader interface {
	Security(string) (ImageSecurity, error)
}

// ImageSecurityCapture connects an existing image reader to CopySecurityFrom.
// Names are fs.ValidPath paths and the final symlink is not followed. Source I/O
// errors remain fatal; image readers do not classify errors for native fstat
// fallback. SecurityRecordDisposition remains available through Reader.Security
// and raw stored bytes through its xattr APIs. No unrelated payload or attribute/
// resource-fork value is loaded here; the bounded security value can be fork-backed.
func ImageSecurityCapture(reader ImageSecurityReader, name string) SecuritySourceCapture {
	return SecuritySourceCapture{ReadSecurity: func() (SecurityCopySource, error) {
		if reader == nil || !fs.ValidPath(name) {
			return SecurityCopySource{}, &fs.PathError{Op: "security", Path: name, Err: fs.ErrInvalid}
		}
		snapshot, err := reader.Security(name)
		return snapshot.Source, err
	}}
}
