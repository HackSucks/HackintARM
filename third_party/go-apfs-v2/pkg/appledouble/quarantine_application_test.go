package appledouble

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
)

type applicationRawProcess struct {
	Code, Errno int
	Flags       uint64
	Agent       string
}
type applicationSnapshot struct {
	Import  *struct{ Code, Errno int }
	Present bool
	Bytes   string
}
type applicationFixtureCase struct {
	Name, Kind string
	FileInput  []byte
	Result     struct {
		DestinationBefore *struct{ Mode uint32 }
		Start, End        int64
		Requested         *string
		ProcessApplyCode  int
		Effective         struct {
			InitCode, InitErrno int
			Serialized          string
			Raw                 *struct{ Self applicationRawProcess }
		}
		Prepared, Applied             applicationSnapshot
		FileApplyCode, FileApplyErrno int
	}
}

func applicationHex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestNativeQuarantineApplication(t *testing.T) {
	for _, corpus := range []struct {
		name    string
		profile QuarantineProfile
		count   int
	}{
		{"destinations-macos26.json.gz", QuarantineMacOS26, 2499},
		{"destinations-macos27.json.gz", QuarantineMacOS27, 2499},
		{"existing-macos26.json.gz", QuarantineMacOS26, 6672},
		{"existing-macos27.json.gz", QuarantineMacOS27, 6672},
		{"contexts-macos26.json.gz", QuarantineMacOS26, 3324},
		{"contexts-macos27.json.gz", QuarantineMacOS27, 3328},
		{"contexts-macos27-absent.json.gz", QuarantineMacOS27, 3328},
		{"existing-macos27-absent.json.gz", QuarantineMacOS27, 6672},
		{"destinations-macos27-absent.json.gz", QuarantineMacOS27, 2499},
		{"processes-macos26.json.gz", QuarantineMacOS26, 4388},
		{"processes-macos27.json.gz", QuarantineMacOS27, 4396},
		{"raw-processes-macos26.json.gz", QuarantineMacOS26, 4388},
		{"raw-processes-macos27.json.gz", QuarantineMacOS27, 4396},
		{"raw-processes-macos27-absent.json.gz", QuarantineMacOS27, 4396},
		{"runtime-macos26.json", QuarantineMacOS26, 768},
		{"runtime-macos27.json", QuarantineMacOS27, 768},
		{"runtime-macos27-no-creation.json.gz", QuarantineMacOS27, 768},
		{"normalization-macos27.json.gz", QuarantineMacOS27, 2218},
		{"normalization-macos26.json.gz", QuarantineMacOS26, 2210},
	} {
		t.Run(corpus.name, func(t *testing.T) {
			b, e := os.ReadFile("../../testdata/appledouble/native/quarantine-" + corpus.name)
			if e != nil {
				t.Fatal(e)
			}
			if strings.HasSuffix(corpus.name, ".gz") {
				z, e := gzip.NewReader(bytes.NewReader(b))
				if e != nil {
					t.Fatal(e)
				}
				b, e = io.ReadAll(z)
				if e != nil {
					t.Fatal(e)
				}
				if e = z.Close(); e != nil {
					t.Fatal(e)
				}
			}
			var f struct{ Records []applicationFixtureCase }
			if e = json.Unmarshal(b, &f); e != nil {
				t.Fatal(e)
			}
			if len(f.Records) != corpus.count {
				t.Fatal("native case count", len(f.Records))
			}
			for _, tc := range f.Records {
				t.Run(tc.Name, func(t *testing.T) { verifyApplicationFixture(t, tc, corpus.profile) })
			}
		})
	}
}
func verifyApplicationFixture(t *testing.T, tc applicationFixtureCase, profile QuarantineProfile) {
	t.Helper()
	r := tc.Result
	q, e := ParseQuarantineWithProfile(tc.FileInput, profile)
	if e != nil {
		t.Fatal(e)
	}
	ctx := QuarantineApplicationContext{Profile: profile, Timestamp: uint32(r.Start), Directory: tc.Kind == "directory"}
	if r.DestinationBefore != nil {
		ctx.Directory = false
		switch tc.Kind {
		case "file":
			ctx.Kind = QuarantineRegularFile
		case "directory":
			ctx.Kind = QuarantineDirectory
		case "symlink-file", "symlink-directory", "symlink-dangling":
			ctx.Kind = QuarantineSymlink
		default:
			t.Fatal("unknown native destination kind", tc.Kind)
		}
	}
	if r.Effective.InitCode == 0 && r.Effective.Raw == nil {
		// Captures use the canonical process envelope. Reuse the established field
		// decoder by inserting a timestamp; no requested state supplies policy input.
		p := applicationHex(t, r.Effective.Serialized)
		envelope := append(bytes.Clone(p[:7]), []byte("00000000;")...)
		envelope = append(envelope, p[7:]...)
		captured, e := ParseQuarantineWithProfile(envelope, profile)
		if e != nil {
			t.Fatal(e)
		}
		ctx.Process = &QuarantineProcess{Flags: captured.Flags, Agent: captured.Agent} // Process capture can decode a raw kernel backslash a second time. In
		// these controlled experiments, a successful request supplies the known
		// raw agent; effective flags still come from the independent capture.
		if r.Requested != nil && r.ProcessApplyCode == 0 {
			request := applicationHex(t, *r.Requested)
			b := append(bytes.Clone(request[:7]), []byte("00000000;")...)
			b = append(b, request[7:]...)
			requested, err := ParseQuarantineWithProfile(b, profile)
			if err != nil {
				t.Fatal(err)
			}
			ctx.Process.Agent = requested.Agent
		}

	}
	if raw := r.Effective.Raw; raw != nil {
		ctx.Process = nil
		if raw.Self.Code == 0 {
			ctx.Process = &QuarantineProcess{Flags: uint32(raw.Self.Flags), Agent: string(applicationHex(t, raw.Self.Agent))}
		} else if raw.Self.Code == -1 && raw.Self.Errno == 93 && r.Effective.InitCode == -1 && r.Effective.InitErrno == 93 {
			ctx.Process = &QuarantineProcess{Absent: true}
		}
	}
	before := applicationHex(t, r.Prepared.Bytes)
	after := applicationHex(t, r.Applied.Bytes)
	if r.Prepared.Import != nil {
		if r.Prepared.Present {
			ctx.ExistingXattr = append([]byte{}, before...)
		}
	} else if r.Prepared.Present {
		ctx.Existing, e = ParseQuarantineXattrWithProfile(before, profile)
		if e != nil {
			t.Fatal(e)
		}
	}
	original := *q
	got, e := q.PlanApplication(ctx)
	if *q != original {
		t.Fatal("mutated source model")
	}
	if ctx.Process == nil {
		if !errors.Is(e, ErrQuarantineContext) || got != nil {
			t.Fatal("unavailable capture must not choose policy", got, e)
		}
		return
	}
	switch r.FileApplyCode {
	case 22:
		if r.FileApplyErrno != 22 || !errors.Is(e, ErrQuarantineExisting) || got != nil {
			t.Fatal("native malformed existing-header failure", got, e)
		}
	case 34:
		if !errors.Is(e, ErrQuarantineApplicationSize) || got != nil {
			t.Fatal("native application range failure", got, e)
		}
	case -1:
		if r.FileApplyErrno != 93 || !errors.Is(e, ErrQuarantineMissing) || got != nil {
			t.Fatal("native missing attribute failure", got, e)
		}
	case 0:
		if e != nil || got == nil {
			t.Fatal(got, e)
		}
		if !got.Write {
			if got.Value != nil || r.Prepared.Present != r.Applied.Present || !bytes.Equal(before, after) {
				t.Fatal("native preservation differs", got)
			}
			return
		}
		if !r.Applied.Present {
			t.Fatal("Go writes but native leaves attribute absent")
		}
		actual := bytes.Clone(after)
		// Allow only a native current timestamp independently bounded by the call.
		if len(got.Value) >= 13 && string(got.Value[5:13]) == strconv.FormatInt(r.Start, 16) {
			if len(actual) < 13 {
				t.Fatalf("native value has no current timestamp: %q", actual)
			}
			stamp, err := strconv.ParseInt(string(actual[5:13]), 16, 64)
			if err != nil || stamp < r.Start || stamp > r.End {
				t.Fatal("native current time outside call", string(actual), err)
			}
			copy(actual[5:13], got.Value[5:13])
		}
		if !bytes.Equal(got.Value, actual) {
			t.Fatalf("Go %q native %q", got.Value, after)
		}
		return
	default:
		t.Fatal("unclassified native application failure", r.FileApplyCode, r.FileApplyErrno)
	}
	if r.Prepared.Present != r.Applied.Present || !bytes.Equal(before, after) {
		t.Fatal("native error changed destination")
	}
}

func TestQuarantineApplicationValidationAndOwnership(t *testing.T) {
	q := &Quarantine{Flags: 1, Timestamp: 17, Agent: "Source", Identifier: "ID"}
	process := &QuarantineProcess{Flags: 0x201, Agent: "Process"}
	existing := &Quarantine{Flags: 0x86, Timestamp: 99, Agent: "Existing", Identifier: "Old"}
	ctx := QuarantineApplicationContext{Process: process, Existing: existing, Timestamp: 123}
	want := *existing
	original := *process
	a, e := q.PlanApplication(ctx)
	if e != nil {
		t.Fatal(e)
	}
	b, e := q.PlanApplication(ctx)
	if e != nil {
		t.Fatal(e)
	}
	a.Value[0] = 'X'
	if string(b.Value) != "0081;0000007b;Process;ID" || *existing != want || *process != original {
		t.Fatal("aliased/mutated application inputs or output")
	}
	for _, bad := range []*Quarantine{nil, {Flags: 0x4000}, {Agent: strings.Repeat("A", 256)}, {Identifier: "x\x00y"}} {
		if p, e := bad.PlanApplication(ctx); p != nil || !errors.Is(e, ErrQuarantine) {
			t.Fatal("invalid model", p, e)
		}
	}
	ctx.Existing = &Quarantine{Flags: 0x4000}
	if _, e = q.PlanApplication(ctx); !errors.Is(e, ErrQuarantine) {
		t.Fatal(e)
	}
	ctx.Existing = nil
	ctx.Profile = 255
	if _, e = q.PlanApplication(ctx); !errors.Is(e, ErrQuarantine) {
		t.Fatal(e)
	}
	ctx.Profile = QuarantineMacOS27
	for _, bad := range []*QuarantineProcess{nil, {}, {Flags: 0x20}, {Flags: 0x1ff}, {Flags: 0x220}, {Flags: 0x201, Agent: strings.Repeat("X", 256)}, {Flags: 0x201, Agent: "A\x00B"}} {
		ctx.Process = bad
		if p, e := q.PlanApplication(ctx); p != nil || !errors.Is(e, ErrQuarantineContext) {
			t.Fatal("unqualified process", p, e)
		}
	}
	ctx.Profile = QuarantineMacOS26
	for _, flags := range []uint32{0, 0x20, 0x200, 0x21f, 0xffffffff} {
		ctx.Process = &QuarantineProcess{Flags: flags}
		if p, e := q.PlanApplication(ctx); p != nil || !errors.Is(e, ErrQuarantineContext) {
			t.Fatal("unqualified macOS 26 process", flags, p, e)
		}
	}
	for _, bad := range []*QuarantineProcess{{Absent: true, Flags: 1}, {Absent: true, Agent: "unproven"}} {
		ctx.Process = bad
		if p, e := q.PlanApplication(ctx); p != nil || !errors.Is(e, ErrQuarantineContext) {
			t.Fatal("contradictory absent context", p, e)
		}
	}
	ctx.Profile = QuarantineMacOS27
	ctx.Process = &QuarantineProcess{Flags: 0x201}
	ctx.Existing = existing
	q.Flags = 8
	a, e = q.PlanApplication(ctx)
	if e != nil || a.Write || a.Value != nil || *existing != want {
		t.Fatal("preservation", a, e)
	}
	// Zero source flags normalize exactly like a parsed native envelope.
	q.Flags = 0
	a, e = q.PlanApplication(ctx)
	if e != nil || !bytes.HasPrefix(a.Value, []byte("0081;")) {
		t.Fatal(a, e)
	}
	// The kernel writes decoded process bytes directly, including semicolons.
	ctx.Process.Agent = "A;B\\x41"
	q.Flags = 1
	a, e = q.PlanApplication(ctx)
	if e != nil || !bytes.Contains(a.Value, []byte(";A;B\\x41;ID")) {
		t.Fatal(a, e)
	}
}

func FuzzQuarantineApplication(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 'A', 'B'})
	f.Add([]byte{1, 0, 0, 4, 'A', 'B'})
	f.Add([]byte{0x40, 0, 1, 6, ';', '\\'})
	f.Add([]byte{1, 0, 1, 16, 'A', 'B'})
	f.Add(bytes.Repeat([]byte{0xff}, 80))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) < 4 {
			return
		}
		profile := QuarantineMacOS26
		if b[2]&1 != 0 {
			profile = QuarantineMacOS27
		}
		flags := uint32(b[0]) | uint32(b[1]&0x1f)<<8
		pflags := uint32(b[2])%31 + 1
		if profile == QuarantineMacOS27 {
			pflags |= 0x200
		}
		q := &Quarantine{Flags: flags, Agent: string(b[4:]), Identifier: string(b[4:]), Timestamp: 17}
		ctx := QuarantineApplicationContext{Profile: profile, Process: &QuarantineProcess{Flags: pflags, Agent: string(b[4:])}, Timestamp: 23, Directory: b[3]&1 != 0}
		ctx.Kind = QuarantineDestinationKind(b[3] >> 3)
		if b[3]&4 != 0 {
			ctx.Process = &QuarantineProcess{Absent: true}
		}
		if b[3]&2 != 0 {
			ctx.Existing = &Quarantine{Flags: uint32(b[3]), Agent: "Existing", Timestamp: 1}
		}
		before := *q
		a, e := q.PlanApplication(ctx)
		if *q != before {
			t.Fatal("source mutation")
		}
		if e != nil {
			if a != nil {
				t.Fatal("error requests a write")
			}
			return
		}
		if a == nil || (!a.Write && a.Value != nil) || len(a.Value) > MaxQuarantineApplicationSize {
			t.Fatal("invalid application plan", a)
		}
		again, e := q.PlanApplication(ctx)
		if e != nil || a.Write != again.Write || !bytes.Equal(a.Value, again.Value) {
			t.Fatal("nondeterministic policy", e)
		}
	})
}
