package apfs

import "testing"

// TestIsEncryptedReadsTheFlagInverted pins the sense of APFS_FS_UNENCRYPTED,
// which is the easiest thing here to get backwards: the flag says the volume is
// *un*encrypted, so a volume with no flags set at all is encrypted. Reading it
// the other way round would treat every FileVault volume as plaintext, which is
// exactly what this package used to do.
func TestIsEncryptedReadsTheFlagInverted(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags uint64
		want  bool
	}{
		{"no flags at all", 0, true},
		{"unencrypted", VolumeFlagUnencrypted, false},
		{"one key, encrypted", VolumeFlagOneKey, true},
		{"unencrypted alongside other flags", VolumeFlagUnencrypted | VolumeFlagSpilledOver, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := &Volume{Superblock: &VolumeSuperblock{VolumeFlags: tc.flags}}
			got, err := v.IsEncrypted()
			if err != nil {
				t.Fatalf("IsEncrypted: %v", err)
			}
			if got != tc.want {
				t.Errorf("IsEncrypted() = %v, want %v (flags %#x)", got, tc.want, tc.flags)
			}
		})
	}
}

// TestEncryptionContextForKeyPicksTheCipherByLength covers both FileVault
// ciphers. An XTS key is a data key and a tweak key end to end, so the length
// is what distinguishes them.
func TestEncryptionContextForKeyPicksTheCipherByLength(t *testing.T) {
	for _, tc := range []struct {
		name       string
		keyLen     int
		wantMethod EncryptionMethod
	}{
		{"AES-128-XTS", 32, EncryptionMethodAES128XTS},
		{"AES-256-XTS", 64, EncryptionMethodAES256XTS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			context, err := NewEncryptionContextForKey(make([]byte, tc.keyLen))
			if err != nil {
				t.Fatalf("NewEncryptionContextForKey(%d bytes): %v", tc.keyLen, err)
			}
			if context.Method != uint32(tc.wantMethod) {
				t.Errorf("method = %d, want %d", context.Method, tc.wantMethod)
			}
		})
	}

	// A length that is not a whole XTS key would silently produce a context
	// that decrypts to noise, so it is refused.
	for _, bad := range []int{0, 16, 31, 48, 65} {
		if _, err := NewEncryptionContextForKey(make([]byte, bad)); err == nil {
			t.Errorf("a %d-byte master key was accepted", bad)
		}
	}
}

// TestLockedVolumeReportsItself is the safety property: an encrypted volume
// that has not been unlocked must say so, because the alternative is a caller
// reading ciphertext and getting structural parse errors that name the wrong
// problem.
func TestLockedVolumeReportsItself(t *testing.T) {
	v := &Volume{Superblock: &VolumeSuperblock{}, isLocked: true}
	locked, err := v.IsLocked()
	if err != nil {
		t.Fatalf("IsLocked: %v", err)
	}
	if !locked {
		t.Error("a locked volume reported itself unlocked")
	}

	// With no keybag there is nothing to unlock it with, and that is an
	// answer rather than an error.
	unlocked, err := v.Unlock()
	if err != nil {
		t.Errorf("Unlock on a volume with no keybag: %v", err)
	}
	if unlocked {
		t.Error("Unlock claimed success with no keybag to unlock from")
	}
}

// TestUnencryptedVolumeIsNeverLocked guards the common path: nothing about this
// change may make a plain volume look like it needs a password.
func TestUnencryptedVolumeIsNeverLocked(t *testing.T) {
	v := &Volume{Superblock: &VolumeSuperblock{VolumeFlags: VolumeFlagUnencrypted}}
	if err := v.openEncryption(nil); err != nil {
		t.Fatalf("openEncryption on an unencrypted volume: %v", err)
	}
	if locked, _ := v.IsLocked(); locked {
		t.Error("an unencrypted volume reported itself locked")
	}
	if v.EncryptionContext != nil {
		t.Error("an unencrypted volume was given an encryption context")
	}
	if unlocked, err := v.Unlock(); err != nil || !unlocked {
		t.Errorf("Unlock on an unencrypted volume = %v, %v; want true, nil", unlocked, err)
	}
}
