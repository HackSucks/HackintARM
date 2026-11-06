package hostdata

func nativeCompressionPathXattr(path, name string, buffer []byte) (int, error) {
	return darwinGetXattrPath(path, name, buffer, xattrCompressionFlags)
}
