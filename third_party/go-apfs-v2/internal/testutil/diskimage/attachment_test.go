package diskimage

import (
	"howett.net/plist"
	"testing"
)

func TestAttachmentDevice(t *testing.T) {
	for _, tc := range []struct {
		name    string
		devices []string
		want    string
	}{
		{"partitioned", []string{"/dev/disk7", "/dev/disk7s1", "/dev/disk7s2"}, "/dev/disk7"},
		{"synthesized-apfs", []string{"/dev/disk7", "/dev/disk7s1", "/dev/disk8", "/dev/disk8s1"}, "/dev/disk7"},
		{"raw-hfs", []string{"/dev/disk17"}, "/dev/disk17"},
		{"slice-first", []string{"/dev/disk7s1", "/dev/disk7"}, "/dev/disk7"},
		{"empty", nil, ""},
		{"slice-only", []string{"/dev/disk7s1"}, ""},
		{"invalid", []string{"/dev/disk", "/dev/disk7/other", "/tmp/dev/disk7", "/dev/disk7\n", "/Volumes/fixture", "/dev/rdisk7"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var entities []map[string]string
			for _, device := range tc.devices {
				entities = append(entities, map[string]string{"dev-entry": device})
			}
			for _, format := range []int{plist.XMLFormat, plist.BinaryFormat} {
				data, err := plist.Marshal(map[string]any{"system-entities": entities}, format)
				if err != nil {
					t.Fatal(err)
				}
				got, err := AttachmentDevice(data)
				if got != tc.want || (err == nil) != (tc.want != "") {
					t.Fatal(got, err, tc.want)
				}
			}
		})
	}
	for _, data := range [][]byte{nil, []byte("not a plist"), []byte(`<?xml version="1.0"?><plist><string>wrong type</string></plist>`)} {
		if got, err := AttachmentDevice(data); err == nil || got != "" {
			t.Fatal(got, err)
		}
	}
}
