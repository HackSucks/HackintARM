//go:build darwin && native_quarantine_oracle

// Package quarantineoracle binds the independent C observer into the same test
// process. It is never imported by production. The qualification driver replaces
// the library marker through a Go build overlay and retains the generated source.
package quarantineoracle

import (
	"syscall"
	"unsafe"
)

//go:linkname syscall6 syscall.syscall6
func syscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, errno syscall.Errno)

//go:linkname syscall9 syscall.syscall9
func syscall9(fn, a1, a2, a3, a4, a5, a6, a7, a8, a9 uintptr) (r1, r2 uintptr, errno syscall.Errno)

var captureAddress, applyAddress uintptr

//go:cgo_import_dynamic captureNative appledouble_quarantine_capture "APFS_QUARANTINE_ORACLE_LIBRARY"
//go:cgo_import_dynamic applyNative appledouble_quarantine_apply "APFS_QUARANTINE_ORACLE_LIBRARY"

// Capture runs the unchanged independent C observer in this process.
func Capture(agent *byte, agentLength *uint64, metadata *byte, metadataLength *uint64, tracking *byte, trackingLength, flags *uint64, errno *int32) int32 {
	result, _, _ := syscall9(captureAddress, uintptr(unsafe.Pointer(agent)), uintptr(unsafe.Pointer(agentLength)), uintptr(unsafe.Pointer(metadata)), uintptr(unsafe.Pointer(metadataLength)), uintptr(unsafe.Pointer(tracking)), uintptr(unsafe.Pointer(trackingLength)), uintptr(unsafe.Pointer(flags)), uintptr(unsafe.Pointer(errno)), 0)
	return int32(result)
}

// Apply invokes libquarantine independently of the Go policy implementation.
func Apply(fd int32, data *byte, length uint64) int32 {
	result, _, _ := syscall6(applyAddress, uintptr(fd), uintptr(unsafe.Pointer(data)), uintptr(length), 0, 0, 0)
	return int32(result)
}
