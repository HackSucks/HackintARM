package hostdata

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// EFS CopyFileEx preserves encrypted streams and keys but does not copy EAs.
// Transfer raw FILE_FULL_EA_INFORMATION records so flags, OEM names and values
// are preserved; the public portable xattr name restrictions do not apply here.
func copyReplacementEAs(ctx context.Context, source, target *os.File) error {
	_, err := replacementWithHandle(ctx, func() (*os.File, error) {
		return reopenReplacementFile(source, windows.FILE_READ_EA)
	}, func(input *os.File) (*os.File, error) {
		return nil, copyReplacementEARecords(ctx, func(buffer []byte, restart bool) (uintptr, bool, error) {
			var status windows.IO_STATUS_BLOCK
			e := windows.NtQueryEaFile(windows.Handle(input.Fd()), &status, &buffer[0], uint32(len(buffer)), true, nil, 0, nil, restart)
			if errors.Is(e, windows.STATUS_NO_MORE_EAS) || (restart && errors.Is(e, windows.STATUS_NO_EAS_ON_FILE)) {
				return 0, true, nil
			}
			return status.Information, false, e
		}, func(record []byte) error {
			return replacementFileControl(target, func(handle windows.Handle) error {
				return windows.NtSetEaFile(handle, &windows.IO_STATUS_BLOCK{}, &record[0], uint32(len(record)))
			})
		})
	})
	return err
}

func copyReplacementEARecords(ctx context.Context, query func([]byte, bool) (uintptr, bool, error), write func([]byte) error) error {
	// Native field widths bound one record: fixed header, uint8 name, NUL and
	// uint16 value. Total record count and total value bytes are not capped.
	buffer := make([]byte, 8+255+1+65535)
	restart := true
	for {
		var end bool
		n, err := replacementValue(ctx, func() (uintptr, error) { size, done, e := query(buffer, restart); end = done; return size, e })
		if err != nil {
			return err
		}
		if end {
			return nil
		}
		if n < 9 || n > uintptr(len(buffer)) {
			return fmt.Errorf("invalid native EA extent")
		}
		record := buffer[:n]
		nameSize := int(record[5])
		valueSize := int(binary.LittleEndian.Uint16(record[6:8]))
		size := 8 + nameSize + 1 + valueSize
		if binary.LittleEndian.Uint32(record[:4]) != 0 || nameSize == 0 || size > len(record) || record[8+nameSize] != 0 {
			return fmt.Errorf("invalid native single EA record")
		}
		if err = replacementStep(ctx, func() error { return write(record[:size]) }); err != nil {
			return err
		}
		restart = false
	}
}
