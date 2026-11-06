//go:build windows && (386 || arm)

package hostdata

import "golang.org/x/sys/windows"

// On 32-bit Windows each by-value LARGE_INTEGER occupies two argument words.
var replacementCopyCallback = windows.NewCallback(func(_, _, _, _, _, _, _, _ uintptr, _ uint32, reason uint32, source, destination, data uintptr) uintptr {
	return replacementCopyProgress(reason, source, destination, data)
})
