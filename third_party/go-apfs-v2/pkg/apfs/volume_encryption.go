// Unlocking an encrypted (FileVault) volume with a supplied password.
//
// Nothing here decides how APFS encrypts anything: the format is the published
// one, and every primitive it needs already existed unused. The keys travel a
// fixed path, and this file is that path joined up:
//
//	container keybag  -- names where a volume's own keybag lives, and holds
//	                     that volume's master key wrapped by the volume key
//	volume keybag     -- holds the key-encryption keys, one per crypto user
//	password          -- unwraps a KEK (PBKDF2, then RFC 3394) to the volume key
//	volume key        -- unwraps the master key from the container keybag
//	master key        -- the AES-XTS key everything on the volume is read with
package apfs

import (
	"fmt"
	"io"
)

// openEncryption reads the volume's keybag and unlocks it when a password
// fits, leaving v.EncryptionContext set. It is called during OpenRead, before
// anything encrypted is read.
//
// A volume that is encrypted and cannot be unlocked is left locked rather than
// refused: the caller is told by IsLocked, and the read paths refuse. That
// distinction is what lets `info` describe a locked volume instead of failing
// with a structural error from parsing ciphertext.
func (v *Volume) openEncryption(reader io.ReaderAt) error {
	encrypted, err := v.IsEncrypted()
	if err != nil {
		return err
	}
	if !encrypted {
		return nil
	}

	// From here the volume is known to be encrypted, so it is locked until a
	// key says otherwise. Setting this first means every early return below
	// leaves the volume safely locked rather than apparently readable.
	v.isLocked = true

	if v.ContainerKeybag == nil {
		// Encrypted with no container keybag to find the keys in. Nothing can
		// unlock it, and saying so is better than reading ciphertext.
		return nil
	}

	volumeUUID := v.Superblock.VolumeUUID
	blockNumber, blockCount, found, err := v.ContainerKeybag.VolumeKeybagExtentByIdentifier(volumeUUID[:])
	if err != nil {
		return fmt.Errorf("unable to locate the volume keybag: %w", err)
	}
	if !found || blockCount == 0 {
		return nil
	}

	keybag := NewVolumeKeybagOrNil()
	if keybag == nil {
		return fmt.Errorf("unable to create volume keybag")
	}
	offset := int64(blockNumber) * int64(v.IOHandle.BlockSize)
	size := blockCount * uint64(v.IOHandle.BlockSize)
	if err := keybag.ReadFrom(v.IOHandle, reader, offset, size, volumeUUID[:]); err != nil {
		// A keybag that will not parse is a locked volume, not a broken one:
		// the usual cause is that this is not the keybag layout we know.
		return nil
	}
	v.VolumeKeybag = keybag

	if _, err := v.Unlock(); err != nil {
		return err
	}
	return nil
}

// NewVolumeKeybagOrNil returns a new volume keybag, or nil if one cannot be
// made. It exists so openEncryption reads as one path rather than a ladder.
func NewVolumeKeybagOrNil() *VolumeKeybag {
	keybag, err := NewVolumeKeybag()
	if err != nil {
		return nil
	}
	return keybag
}

// unlockWith tries one pair of passwords against the volume keybag and, if a
// key comes back, builds the encryption context from it.
func (v *Volume) unlockWith(userPassword, recoveryPassword []byte) (bool, error) {
	volumeKey, ok, err := v.VolumeKeybag.VolumeKey(userPassword, recoveryPassword)
	if err != nil || !ok {
		// A password that does not fit is not an error: it is the answer.
		return false, nil
	}

	volumeUUID := v.Superblock.VolumeUUID
	masterKey, found, err := v.ContainerKeybag.VolumeMasterKeyByIdentifier(volumeUUID[:], volumeKey)
	if err != nil {
		return false, fmt.Errorf("unable to unwrap the volume master key: %w", err)
	}
	if !found {
		return false, fmt.Errorf("the container keybag holds no master key for volume %x", volumeUUID)
	}

	context, err := NewEncryptionContextForKey(masterKey)
	if err != nil {
		return false, fmt.Errorf("unable to prepare decryption: %w", err)
	}
	v.EncryptionContext = context
	v.isLocked = false
	return true, nil
}

// Unlock attempts to unlock an encrypted volume with the passwords already set
// on it. It reports whether the volume ended up unlocked.
//
// An unencrypted volume, or one already unlocked, reports true and does
// nothing. A wrong password reports false with no error: failing to guess a
// password is an answer, not a failure.
func (v *Volume) Unlock() (bool, error) {
	if v == nil {
		return false, fmt.Errorf("invalid volume")
	}
	if v.Superblock == nil {
		return false, fmt.Errorf("invalid volume - missing superblock")
	}
	if !v.isLocked {
		return true, nil
	}
	if v.VolumeKeybag == nil || v.ContainerKeybag == nil {
		return false, nil
	}
	return v.unlockWith(v.UserPassword, v.RecoveryPassword)
}
