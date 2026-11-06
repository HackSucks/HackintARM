//go:build !darwin

package hostdata

func listCaptureXattrFD(fd, limit int) ([]string, error) {
	return listVisibleXattrFD(fd, limit)
}

func getCaptureXattrFD(fd int, name string, buf []byte) (int, error) {
	return getVisibleXattrFD(fd, name, buf)
}
