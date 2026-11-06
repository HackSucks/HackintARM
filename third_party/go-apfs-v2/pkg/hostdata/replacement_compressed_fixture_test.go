package hostdata

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/captureprovenance"
)

func TestReplacementCompressedNativeFixture(t *testing.T) {
	b, err := os.ReadFile("../../testdata/appledouble/native/replacement-compressed.json")
	if err != nil {
		t.Fatal(err)
	}
	var capture struct {
		Schema int               `json:"schema"`
		Hashes map[string]string `json:"source_sha256"`
		Cases  []struct {
			Name                        string `json:"case"`
			Filesystem                  string `json:"filesystem"`
			Type                        uint32 `json:"type"`
			Source, Replacement, Native map[string]json.RawMessage
			Times                       replacementNativeTimes `json:"native_times"`

			SourceUnchanged bool `json:"source_unchanged"`
			StageRemoved    bool `json:"stage_removed"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(b, &capture); err != nil {
		t.Fatal(err)
	}
	if capture.Schema != 2 || len(capture.Cases) != 68 {
		t.Fatalf("incomplete native capture: %d/%d", capture.Schema, len(capture.Cases))
	}
	referenceSources, referenceErr := captureprovenance.Reference(os.DirFS("../.."), capture.Hashes)
	if referenceErr != nil {
		t.Fatal(referenceErr)
	}
	if err := captureprovenance.Verify(referenceSources, capture.Hashes); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"testdata/appledouble/native/replacement-compressed.c", "testdata/appledouble/native/decmpfs-formats.c", "testdata/appledouble/native/decmpfs-formats.json.gz"} {
		b, err := captureprovenance.ReadSource(referenceSources, capture.Hashes, name)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(b)
		if capture.Hashes[name] != hex.EncodeToString(h[:]) {
			t.Fatal("source hash mismatch", name)
		}
	}
	names := map[string]uint32{"producer-3": 4, "producer-7": 8, "producer-11": 12}
	for _, sample := range replacementCompressionSamples(t) {
		names[sample.Name] = sample.Type
	}
	seen := map[string]bool{}
	for _, tc := range capture.Cases {
		key := tc.Filesystem + "/" + tc.Name
		t.Run(key, func(t *testing.T) {
			parts := strings.Split(tc.Name, "/")
			if len(parts) != 3 || parts[0] != "TestReplacementCompressedDarwinNative" || (parts[1] != "path" && parts[1] != "root") {
				t.Fatal("invalid case name", tc.Name)
			}
			if want, ok := names[parts[2]]; !ok || tc.Type != want {
				t.Fatal("unexpected native storage profile", tc.Type)
			}
			if (tc.Filesystem != "APFS" && tc.Filesystem != "HFS+") || seen[key] {
				t.Fatal("duplicate or invalid filesystem", key)
			}
			seen[key] = true
			if !tc.SourceUnchanged || !tc.StageRemoved {
				t.Fatal("incomplete replacement lifecycle")
			}
			var sourceFlags, targetFlags uint32
			if err := json.Unmarshal(tc.Source["Flags"], &sourceFlags); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(tc.Replacement["Flags"], &targetFlags); err != nil {
				t.Fatal(err)
			}
			if sourceFlags&UFCompressed == 0 || targetFlags != sourceFlags&^UFCompressed {
				t.Fatal("invalid compression transition")
			}
			if !bytes.Equal(tc.Source["Birth"], tc.Replacement["Birth"]) {
				t.Fatal("SDK lost source birth time")
			}
			var nativeBirth, sourceBirth replacementNativeTime
			if err := json.Unmarshal(tc.Native["Birth"], &nativeBirth); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(tc.Source["Birth"], &sourceBirth); err != nil {
				t.Fatal(err)
			}
			if err := tc.Times.validate(nativeBirth); err != nil {
				t.Fatal(err)
			}
			if tc.Times.SourceModified != (replacementNativeTime{1610000000, 0}) || nativeBirth == sourceBirth {
				t.Fatal("missing deterministic birth-clamping control")
			}
			for _, field := range []string{"Mode", "UID", "GID", "Flags", "Attributes", "ForkSize", "ForkSHA256", "ACL"} {
				if tc.Replacement[field] == nil || !bytes.Equal(tc.Replacement[field], tc.Native[field]) {
					t.Fatal("native metadata mismatch", field)
				}
			}
			var sourceAttrs, attrs map[string]string
			if err := json.Unmarshal(tc.Source["Attributes"], &sourceAttrs); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(tc.Replacement["Attributes"], &attrs); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(attrs, sourceAttrs) || attrs[DecmpfsName] != "" || attrs["user.replacement"] != hex.EncodeToString([]byte("independent metadata")) {
				t.Fatal("independent attributes changed")
			}
		})
	}
	for _, fs := range []string{"APFS", "HFS+"} {
		for _, api := range []string{"path", "root"} {
			for name := range names {
				if !seen[fs+"/TestReplacementCompressedDarwinNative/"+api+"/"+name] {
					t.Fatal("missing exact native case", fs, api, name)
				}
			}
		}
	}
}

// Keep the native intermediate observations in the portable corpus so the
// filesystem's timestamp clamping is checked independently of Go wall time.
type replacementNativeTime struct{ Sec, Nsec int64 }
type replacementNativeTimes struct {
	SourceModified replacementNativeTime `json:"source_modified"`
	Created        replacementNativeTime `json:"created"`
	CopiedBirth    replacementNativeTime `json:"copied_birth"`
	CopiedModified replacementNativeTime `json:"copied_modified"`
	RewrittenBirth replacementNativeTime `json:"rewritten_birth"`
}

func (times replacementNativeTimes) validate(final replacementNativeTime) error {
	expected := times.Created
	if times.SourceModified.Sec < expected.Sec ||
		(times.SourceModified.Sec == expected.Sec && times.SourceModified.Nsec < expected.Nsec) {
		expected = times.SourceModified
	}
	if times.Created.Sec == 0 || times.SourceModified.Sec == 0 ||
		times.CopiedModified != times.SourceModified || times.CopiedBirth != expected ||
		times.RewrittenBirth != expected || final != expected {
		return fmt.Errorf("native timestamp transition: %+v final %+v expected birth %+v", times, final, expected)
	}
	return nil
}

func TestReplacementNativeTimestampOracle(t *testing.T) {
	early := replacementNativeTime{1610000000, 123}
	late := replacementNativeTime{1710000000, 456}
	for _, tc := range []struct {
		name                        string
		modified, created, expected replacementNativeTime
	}{
		{"older-mtime-clamps", early, late, early},
		{"newer-mtime-preserves", late, early, early},
		{"equal-times", early, early, early},
		{"nanosecond-clamp", replacementNativeTime{1710000000, 123}, late, replacementNativeTime{1710000000, 123}},
		{"nanosecond-preserve", late, replacementNativeTime{1710000000, 123}, replacementNativeTime{1710000000, 123}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			valid := replacementNativeTimes{tc.modified, tc.created, tc.expected, tc.modified, tc.expected}
			if err := valid.validate(tc.expected); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"source", "created", "copied-birth", "copied-mtime", "rewritten-birth", "final"} {
				t.Run(field, func(t *testing.T) {
					altered, final := valid, tc.expected
					switch field {
					case "source":
						altered.SourceModified = replacementNativeTime{}
					case "created":
						altered.Created = replacementNativeTime{}
					case "copied-birth":
						altered.CopiedBirth.Nsec++
					case "copied-mtime":
						altered.CopiedModified.Nsec++
					case "rewritten-birth":
						altered.RewrittenBirth.Nsec++
					case "final":
						final.Nsec++
					}
					if err := altered.validate(final); err == nil {
						t.Fatal("accepted corrupt native transition")
					}
				})
			}
		})
	}
}
