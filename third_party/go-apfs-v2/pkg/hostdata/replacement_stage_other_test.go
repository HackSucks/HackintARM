//go:build !windows

package hostdata

import "os"

func setReplacementTestInfo(r *Replacement, info os.FileInfo) { r.info = info }
