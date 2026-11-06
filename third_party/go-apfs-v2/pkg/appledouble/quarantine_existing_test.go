package appledouble

import (
	"bytes"
	"errors"
	"testing"
)

func TestQuarantineExistingRawState(t *testing.T) {
	q := &Quarantine{Flags: 0x218, Timestamp: 17, Agent: "Source", Identifier: "ID"}
	ctx := QuarantineApplicationContext{Process: &QuarantineProcess{Flags: 0x202, Agent: "Process"}, Timestamp: 123}
	for _, tc := range []struct {
		name  string
		raw   []byte
		err   error
		write string
	}{
		{"absent", nil, ErrQuarantineMissing, ""},
		{"empty", []byte{}, ErrQuarantineExisting, ""},
		{"malformed", []byte("garbage"), ErrQuarantineExisting, ""},
		{"partial", []byte("0006;"), ErrQuarantineExisting, ""},
		{"zero-flags-preserve", []byte("0000;0;A;B"), nil, ""},
		{"unimportable-header", []byte("ffff;0"), nil, "0086;0000007b;Process;ID"},
		{"signed-header", []byte("-006;0"), nil, "0082;0000007b;Process;ID"},
		{"nul-header", []byte("0006\x00;0"), ErrQuarantineExisting, ""},
		{"nul-tail", []byte("0006;0\x00garbage"), nil, "0086;0000007b;Process;ID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx.ExistingXattr = tc.raw
			original := bytes.Clone(tc.raw)
			got, err := q.PlanApplication(ctx)
			if !errors.Is(err, tc.err) || !bytes.Equal(tc.raw, original) {
				t.Fatal(got, err, "mutated", tc.raw)
			}
			if tc.err != nil {
				if got != nil {
					t.Fatal("error requested a write")
				}
				return
			}
			if got == nil || got.Write != (tc.write != "") || string(got.Value) != tc.write {
				t.Fatal(got)
			}
			if len(got.Value) > 0 {
				got.Value[0] = 'X'
				if !bytes.Equal(tc.raw, original) {
					t.Fatal("output aliases raw destination")
				}
			}
		})
	}
	ctx.ExistingXattr = []byte{}
	ctx.Existing = &Quarantine{Flags: 6}
	if got, err := q.PlanApplication(ctx); got != nil || !errors.Is(err, ErrQuarantine) {
		t.Fatal("ambiguous representations", got, err)
	}
	ctx.Existing = nil
	ctx.Process = nil
	if got, err := q.PlanApplication(ctx); got != nil || !errors.Is(err, ErrQuarantineContext) {
		t.Fatal("malformed bytes cannot imply a process context", got, err)
	}
	ctx.Process = &QuarantineProcess{Flags: 0x202}
	large := &Quarantine{Flags: 0x218, Agent: string(bytes.Repeat([]byte{' '}, 100))}
	if got, err := large.PlanApplication(ctx); got != nil || !errors.Is(err, ErrQuarantineApplicationSize) {
		t.Fatal("source size precedes existing header", got, err)
	}
}

func FuzzQuarantineExistingApplication(f *testing.F) {
	for _, seed := range [][]byte{{}, []byte("garbage"), []byte("0006;0"), []byte("ffff;0;A;B"), []byte("0006;0\x00junk")} {
		f.Add(seed, uint16(0x218), true)
	}
	f.Fuzz(func(t *testing.T, raw []byte, flags uint16, sandbox bool) {
		if len(raw) > 8192 {
			return
		}
		q := &Quarantine{Flags: uint32(flags) & 0x3fff, Agent: "Source", Identifier: "ID"}
		process := uint32(0x201)
		if sandbox {
			process = 0x202
		}
		ctx := QuarantineApplicationContext{Process: &QuarantineProcess{Flags: process}, ExistingXattr: raw, Timestamp: 17}
		before := bytes.Clone(raw)
		a, err := q.PlanApplication(ctx)
		b, again := q.PlanApplication(ctx)
		if !errors.Is(err, again) || !bytes.Equal(before, raw) {
			t.Fatal("unstable or mutating plan", err, again)
		}
		if err != nil {
			if a != nil || b != nil || !errors.Is(err, ErrQuarantineExisting) {
				t.Fatal("unexpected error", err)
			}
			return
		}
		if a == nil || b == nil || a.Write != b.Write || !bytes.Equal(a.Value, b.Value) {
			t.Fatal("unstable plan")
		}
		if !a.Write && a.Value != nil {
			t.Fatal("preserve with bytes")
		}
		if a.Write {
			a.Value[0] ^= 1
			if bytes.Equal(a.Value, b.Value) || !bytes.Equal(raw, before) {
				t.Fatal("aliased result")
			}
		}
	})
}
