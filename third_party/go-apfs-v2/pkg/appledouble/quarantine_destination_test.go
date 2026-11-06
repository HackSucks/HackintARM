package appledouble

import (
	"bytes"
	"errors"
	"testing"
)

func TestQuarantineDestinationKinds(t *testing.T) {
	for _, profile := range []QuarantineProfile{QuarantineMacOS26, QuarantineMacOS27} {
		flags := uint32(1)
		if profile == QuarantineMacOS27 {
			flags |= 0x200
		}
		ctx := QuarantineApplicationContext{Profile: profile, Process: &QuarantineProcess{Flags: flags, Agent: "Process"}, Timestamp: 123}
		source := &Quarantine{Flags: 1, Timestamp: 17, Agent: "Source", Identifier: "ID"}
		for _, tc := range []struct {
			kind      QuarantineDestinationKind
			directory bool
			stamp     string
		}{
			{QuarantineRegularFile, false, "0000007b"},
			{QuarantineDirectory, false, "00000000"},
			{QuarantineSymlink, false, "0000007b"},
			{QuarantineRegularFile, true, "00000000"},
			{QuarantineDirectory, true, "00000000"},
		} {
			ctx.Kind, ctx.Directory = tc.kind, tc.directory
			plan, err := source.PlanApplication(ctx)
			if err != nil || plan == nil || !plan.Write || string(plan.Value) != "0081;"+tc.stamp+";Process;ID" {
				t.Fatal(profile, tc, plan, err)
			}
		}
		for _, tc := range []struct {
			kind      QuarantineDestinationKind
			directory bool
		}{{QuarantineSymlink, true}, {3, false}, {255, false}, {255, true}} {
			ctx.Kind, ctx.Directory = tc.kind, tc.directory
			if plan, err := source.PlanApplication(ctx); plan != nil || !errors.Is(err, ErrQuarantineDestination) {
				t.Fatal(profile, tc, plan, err)
			}
		}
		// Kind selection does not change the sandbox source-preserving fallback.
		ctx.Kind, ctx.Directory, ctx.Process.Flags = QuarantineSymlink, false, flags|2
		source.Flags = 0x40
		plan, err := source.PlanApplication(ctx)
		if err != nil || plan == nil || string(plan.Value) != "0081;00000011;Source;ID" {
			t.Fatal(profile, plan, err)
		}
		if profile == QuarantineMacOS26 {
			ctx.Process = &QuarantineProcess{Absent: true}
			source.Flags = 1
			plan, err = source.PlanApplication(ctx)
			if err != nil || plan == nil || string(plan.Value) != "0081;00000011;Source;ID" {
				t.Fatal(plan, err)
			}
		}
	}
}

func TestQuarantineDestinationErrorPrecedence(t *testing.T) {
	ctx := QuarantineApplicationContext{Kind: 255, Process: &QuarantineProcess{Flags: 0x201}}
	q := &Quarantine{Flags: 1, Agent: string(bytes.Repeat([]byte{' '}, 100))}
	if p, err := q.PlanApplication(ctx); p != nil || !errors.Is(err, ErrQuarantineDestination) {
		t.Fatal("kind precedes application size", p, err)
	}
	ctx.Process = nil
	if p, err := q.PlanApplication(ctx); p != nil || !errors.Is(err, ErrQuarantineContext) {
		t.Fatal("unavailable context", p, err)
	}
	q.Flags = 0xffff
	if p, err := q.PlanApplication(ctx); p != nil || !errors.Is(err, ErrQuarantine) {
		t.Fatal("invalid source", p, err)
	}
}
