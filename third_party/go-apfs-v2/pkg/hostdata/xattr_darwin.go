package hostdata

const (
	xattrNoFollow         = 0x0001
	xattrShowCompression  = 0x0020
	xattrCompressionFlags = xattrNoFollow | xattrShowCompression
)

// Capture includes storage attributes hidden from ordinary xattr enumeration.
// Errors must not fall back to an ordinary listing and silently hide content.
func listXattrNames(path string) ([]string, error) {
	return readXattrNames(func(buf []byte) (int, error) {
		return darwinListXattrPath(path, buf, xattrCompressionFlags)
	}, MaxXattrListSize)
}

func getXattr(path, name string) ([]byte, error) {
	value, present, err := readVisibleXattr(func(buf []byte) (int, error) {
		return darwinGetXattrPath(path, name, buf, xattrCompressionFlags)
	}, int(^uint(0)>>1))
	if err == nil && !present {
		return nil, missingXattrError
	}
	return value, err
}
