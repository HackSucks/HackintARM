package hostdata

import "testing"

func TestFilesystemMetadataFATNames(t *testing.T) {
	for _, name := range []string{"FAT", "fat32", "exFAT"} {
		if !filesystemFATName(name) {
			t.Fatal(name)
		}
	}
	for _, name := range []string{"NTFS", "ReFS", "", "FAT-like"} {
		if filesystemFATName(name) {
			t.Fatal(name)
		}
	}
}
