package hostdata

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These documented EFS operations have no typed x/sys wrappers. Unlike
// BackupRead, they support encrypted files and identify recipient/recovery keys.
var replacementEFS = windows.NewLazySystemDLL("advapi32.dll")
var replacementQueryUsers = replacementEFS.NewProc("QueryUsersOnEncryptedFile")
var replacementQueryRecovery = replacementEFS.NewProc("QueryRecoveryAgentsOnEncryptedFile")
var replacementFreeKeys = replacementEFS.NewProc("FreeEncryptionCertificateHashList")

type replacementEFSBlob struct {
	Size uint32
	Data *byte
}
type replacementEFSHash struct {
	Size    uint32
	SID     *windows.SID
	Hash    *replacementEFSBlob
	Display *uint16
}
type replacementEFSList struct {
	Count   uint32
	Entries **replacementEFSHash
}

func replacementQueryEFS(ctx context.Context, path string, query *windows.LazyProc) (*replacementEFSList, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var list *replacementEFSList
	code, _, _ := query.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&list)))
	runtime.KeepAlive(name)
	if code != 0 || ctx.Err() != nil {
		if list != nil {
			freeReplacementEFS(list)
		}
		var native error
		if code != 0 {
			native = windows.Errno(code)
		}
		return nil, errors.Join(native, ctx.Err())
	}
	return list, nil
}

func replacementEFSKeyEqual(a, b *replacementEFSHash) bool {
	if a == nil || b == nil || a.Hash == nil || b.Hash == nil {
		return false
	}
	if (a.SID == nil) != (b.SID == nil) {
		return false
	}
	if a.SID != nil && !windows.EqualSid(a.SID, b.SID) {
		return false
	}
	if a.Hash.Size != b.Hash.Size || uint64(a.Hash.Size) > uint64(int(^uint(0)>>1)) {
		return false
	}
	if a.Hash.Size != 0 && (a.Hash.Data == nil || b.Hash.Data == nil) {
		return false
	}
	return bytes.Equal(unsafe.Slice(a.Hash.Data, int(a.Hash.Size)), unsafe.Slice(b.Hash.Data, int(b.Hash.Size)))
}

// Compare unordered native key lists without constructing a second owned index.
// Count occurrences as well as entries so duplicate hashes cannot hide a loss.
func replacementEFSKeysEqual(a, b *replacementEFSList) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Count != b.Count || uint64(a.Count) > uint64(int(^uint(0)>>1))/uint64(unsafe.Sizeof(a.Entries)) {
		return false
	}
	if a.Count != 0 && (a.Entries == nil || b.Entries == nil) {
		return false
	}
	left, right := unsafe.Slice(a.Entries, int(a.Count)), unsafe.Slice(b.Entries, int(b.Count))
	for _, key := range left {
		first, second := 0, 0
		for _, entry := range left {
			if replacementEFSKeyEqual(key, entry) {
				first++
			}
		}
		for _, entry := range right {
			if replacementEFSKeyEqual(key, entry) {
				second++
			}
		}
		if first == 0 || first != second {
			return false
		}
	}
	return true
}

// Namespace-based EFS APIs run only while a no-delete-share reopen pins the
// selected file. Resolve its path after acquiring that handle, never from Name.
func replacementPinEFS(ctx context.Context, file *os.File) (pin *os.File, err error) {
	pin, err = replacementValue(ctx, func() (*os.File, error) {
		// Attribute-only opens do not participate in Windows sharing checks.
		// FILE_READ_DATA makes the no-delete-share capability an effective pin.
		return reopenReplacementFileSharing(file, windows.FILE_READ_DATA|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
	})
	if err != nil && pin != nil {
		err = errors.Join(err, pin.Close())
		pin = nil
	}
	return pin, err
}

func replacementVerifyEFS(ctx context.Context, source, target *os.File) (err error) {
	basic, err := replacementValue(ctx, func() (replacementBasicInfo, error) { return replacementBasic(source) })
	if err != nil {
		return err
	}
	if basic.Attributes&windows.FILE_ATTRIBUTE_ENCRYPTED == 0 {
		return nil
	}
	targetBasic, err := replacementValue(ctx, func() (replacementBasicInfo, error) { return replacementBasic(target) })
	if err != nil {
		return err
	}
	if targetBasic.Attributes&windows.FILE_ATTRIBUTE_ENCRYPTED == 0 {
		return fmt.Errorf("replacement lost EFS encryption")
	}
	from, err := replacementPinEFS(ctx, source)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, from.Close()) }()
	to, err := replacementPinEFS(ctx, target)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, to.Close()) }()
	sourcePath, err := replacementFinalPath(ctx, from)
	if err != nil {
		return err
	}
	targetPath, err := replacementFinalPath(ctx, to)
	if err != nil {
		return err
	}
	for _, query := range []*windows.LazyProc{replacementQueryUsers, replacementQueryRecovery} {
		original, e := replacementQueryEFS(ctx, sourcePath, query)
		if e != nil {
			return e
		}
		if original != nil {
			defer freeReplacementEFS(original)
		}
		copied, e := replacementQueryEFS(ctx, targetPath, query)
		if e != nil {
			return e
		}
		if copied != nil {
			defer freeReplacementEFS(copied)
		}
		if !replacementEFSKeysEqual(original, copied) {
			return fmt.Errorf("replacement EFS recipient or recovery keys changed")
		}
	}
	return ctx.Err()
}

// FreeEncryptionCertificateHashList returns void; no last-error value belongs to it.
func freeReplacementEFS(list *replacementEFSList) {
	_, _, _ = replacementFreeKeys.Call(uintptr(unsafe.Pointer(list)))
}
