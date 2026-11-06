package appledouble

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// These are filesystem values created under controlled native process contexts,
// paired with an independent qtn_file_init_with_fd/qtn_file_to_data export.
// Replaying imports on every Go OS does not claim to implement native policy.
func TestNativeQuarantineRuntimeImports(t *testing.T) {
	for _, target := range []struct {
		name    string
		profile QuarantineProfile
	}{{"macos26", QuarantineMacOS26}, {"macos27", QuarantineMacOS27}} {
		t.Run(target.name, func(t *testing.T) {
			raw, err := os.ReadFile("../../testdata/appledouble/native/quarantine-runtime-" + target.name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			type snapshot struct {
				Present         bool
				Bytes, Envelope string
			}
			var fixture struct {
				Records []struct {
					Name   string
					Result struct{ Prepared, Applied snapshot }
				}
			}
			if err := json.Unmarshal(raw, &fixture); err != nil {
				t.Fatal(err)
			}
			if len(fixture.Records) != 768 {
				t.Fatal("incomplete native runtime matrix", len(fixture.Records))
			}
			for _, tc := range fixture.Records {
				t.Run(tc.Name, func(t *testing.T) {
					for _, stage := range []struct {
						name  string
						value snapshot
					}{{"prepared", tc.Result.Prepared}, {"applied", tc.Result.Applied}} {
						if !stage.value.Present {
							continue
						}
						t.Run(stage.name, func(t *testing.T) {
							input, err := hex.DecodeString(stage.value.Bytes)
							if err != nil {
								t.Fatal(err)
							}
							expected, err := hex.DecodeString(stage.value.Envelope)
							if err != nil {
								t.Fatal(err)
							}
							q, err := ParseQuarantineXattrWithProfile(input, target.profile)
							if err != nil {
								t.Fatal(err)
							}
							got, err := q.MarshalBinaryWithProfile(target.profile)
							if err != nil || !bytes.Equal(got, expected) {
								t.Fatalf("native runtime import: got %q want %q: %v", got, expected, err)
							}
						})
					}
				})
			}
		})
	}
}
