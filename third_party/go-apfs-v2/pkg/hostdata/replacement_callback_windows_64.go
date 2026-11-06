//go:build windows && (amd64 || arm64)

package hostdata

import "golang.org/x/sys/windows"

// Four LARGE_INTEGER values precede the stream/reason/handle arguments.
var replacementCopyCallback = windows.NewCallback(func(_, _, _, _ uint64, _ uint32, reason uint32, source, destination, data uintptr) uintptr {
	return replacementCopyProgress(reason, source, destination, data)
})
