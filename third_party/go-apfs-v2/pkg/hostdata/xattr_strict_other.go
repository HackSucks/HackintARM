//go:build !darwin && !linux && !windows

package hostdata

func getVisibleXattrFD(int, string, []byte) (int, error)      { return 0, ErrXattrUnsupported }
func getVisibleXattrPath(string, string, []byte) (int, error) { return 0, ErrXattrUnsupported }
func removeVisibleXattrFD(int, string) error                  { return ErrXattrUnsupported }
func removeVisibleXattrPath(string, string) error             { return ErrXattrUnsupported }
func missingXattr(error) bool                                 { return false }
func xattrRangeError(error) bool                              { return false }
func strictXattrError(err error) error                        { return err }

func listVisibleXattrFD(int, int) ([]string, error) { return nil, ErrXattrUnsupported }

func setVisibleXattrFD(int, string, []byte) error { return ErrXattrUnsupported }
