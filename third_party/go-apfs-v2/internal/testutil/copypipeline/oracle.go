// Package copypipeline replays controlled observations of Apple's complete
// copyfile_internal function. It does not simulate native stage side effects.
package copypipeline

import (
	"errors"
	"fmt"
	"os"
	"reflect"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

type Event struct {
	Operation string
	Code      int
	Xattr     string
}
type Observation struct {
	Events           []Event
	Code, StateError int
	CallbackCleared  bool
}
type Case struct {
	Name                                  string
	Flags                                 int
	Source, Destination, Path, Quarantine bool
	Callback                              int    // -99 means no callback
	Codes                                 [8]int // pack, unpack, xattrs, data, security, stat, run-in-place, apply
	Cleanup                               int
	Native                                Observation
}
type Fixture struct {
	Revision, Host, HelperSHA256, CopyfileSHA256 string
	Cases                                        []Case
}

var stages = []hostdata.CopyStage{hostdata.CopyStagePack, hostdata.CopyStageUnpack, hostdata.CopyStageXattrs, hostdata.CopyStageData, hostdata.CopyStageSecurity, hostdata.CopyStageStat, hostdata.CopyStageRunInPlace, hostdata.CopyStageQuarantine}
var injected = errors.New("controlled native operation failure")

type backend struct {
	c      Case
	events []Event
}

func (b *backend) Run(stage hostdata.CopyStage) hostdata.CopyStageResult {
	for i, s := range stages {
		if s == stage {
			code := b.c.Codes[i]
			b.events = append(b.events, Event{Operation: string(s), Code: code})
			r := hostdata.CopyStageResult{Code: code}
			if code != 0 {
				r.Err = injected
			}
			return r
		}
	}
	panic(stage)
}
func (b *backend) RemoveDestination() error {
	b.events = append(b.events, Event{Operation: string(hostdata.CopyStageRemove), Code: b.c.Cleanup})
	if b.c.Cleanup != 0 {
		return injected
	}
	return nil
}
func (b *backend) AllowRunInPlace() hostdata.CopyStageResult {
	return b.Run(hostdata.CopyStageRunInPlace)
}
func (b *backend) Apply() hostdata.CopyStageResult { return b.Run(hostdata.CopyStageQuarantine) }
func Options(c Case) hostdata.CopyPipelineOptions {
	return hostdata.CopyPipelineOptions{SourceReady: c.Source, DestinationReady: c.Destination, HasDestinationPath: c.Path, ACL: c.Flags&1 != 0, Stat: c.Flags&2 != 0, Xattrs: c.Flags&4 != 0, Data: c.Flags&8 != 0, Pack: c.Flags&16 != 0, Unpack: c.Flags&32 != 0, SparseData: c.Flags&64 != 0, RunInPlace: c.Flags&128 != 0}
}
func Replay(c Case) error {
	b := &backend{c: c, events: []Event{}}
	o := Options(c)
	if c.Quarantine {
		o.Quarantine = b
	}
	if c.Callback != -99 {
		o.OnQuarantineError = func(n hostdata.CopyQuarantineNotice) hostdata.CopyPipelineAction {
			b.events = append(b.events, Event{Operation: "callback", Code: c.Callback, Xattr: n.Xattr})
			if n.Result.Code != c.Codes[7] || !errors.Is(n.Result.Err, injected) {
				panic("callback diagnostics")
			}
			return hostdata.CopyPipelineAction(c.Callback)
		}
	}
	r, err := hostdata.RunCopyPipeline(o, b)
	if r.Code != c.Native.Code || r.Completed != (c.Native.Code >= 0) || (err != nil) != (c.Native.Code < 0) || !reflect.DeepEqual(b.events, c.Native.Events) || !c.Native.CallbackCleared {
		return fmt.Errorf("%s: got result %+v, error %v, events %+v; native %+v", c.Name, r, err, b.events, c.Native)
	}
	var want []hostdata.CopyPipelineStep
	for _, e := range b.events {
		if e.Operation == "callback" {
			continue
		}
		s := hostdata.CopyPipelineStep{Stage: hostdata.CopyStage(e.Operation), Result: hostdata.CopyStageResult{Code: e.Code}}
		if e.Code != 0 {
			s.Result.Err = injected
		}
		want = append(want, s)
	}
	if !reflect.DeepEqual(r.Steps, want) {
		return fmt.Errorf("%s: diagnostics mismatch", c.Name)
	}
	switch c.Native.StateError {
	case 22:
		if !errors.Is(err, os.ErrInvalid) {
			return fmt.Errorf("missing invalid error")
		}
	case 0:
	default:
		if c.Codes[7] < 0 {
			if c.Native.StateError != 45 || !errors.Is(err, errors.ErrUnsupported) {
				return fmt.Errorf("missing unsupported error")
			}
			break
		}
		var qe hostdata.CopyQuarantineError
		if !errors.As(err, &qe) || int(qe) != c.Native.StateError {
			return fmt.Errorf("quarantine error mismatch")
		}
	}
	return nil
}

// Cases includes all flag selections, route precedence, missing endpoints,
// independent stop points, positive returns, cleanup failures and callbacks.
func Cases() []Case {
	var cases []Case
	add := func(c Case) { c.Name = fmt.Sprintf("case-%04d", len(cases)); cases = append(cases, c) }
	for flags := 0; flags < 256; flags++ {
		c := Case{Flags: flags, Source: true, Destination: true, Path: true, Callback: -99}
		add(c)
		c.Quarantine = true
		add(c)
	}
	for flags := 0; flags < 256; flags++ {
		for invalid := 0; invalid < 3; invalid++ {
			add(Case{Flags: flags, Source: invalid == 1, Destination: invalid == 2, Path: true, Quarantine: true, Callback: 2})
		}
	}
	for _, flags := range []int{15, 79, 16, 32, 255, 239} {
		for slot := 0; slot < 8; slot++ {
			for _, code := range []int{-7, -1, 1, 13} {
				for _, path := range []bool{false, true} {
					for _, cleanup := range []int{0, -1} {
						c := Case{Flags: flags | 128, Source: true, Destination: true, Path: path, Quarantine: true, Callback: -99, Cleanup: cleanup}
						c.Codes[slot] = code
						add(c)
					}
				}
			}
		}
	}
	for _, flags := range []int{0, 15, 128, 143, 16, 32, 255} {
		for _, code := range []int{0, -7, -1, 1, 13, 45} {
			for _, cb := range []int{-99, -1, 0, 1, 2, 3} {
				c := Case{Flags: flags, Source: true, Destination: true, Path: true, Quarantine: true, Callback: cb}
				c.Codes[7] = code
				add(c)
			}
		}
	}
	// Positive return overwritten by a later stage, retained if no later stage.
	for flags := 0; flags < 16; flags++ {
		add(Case{Flags: flags, Source: true, Destination: true, Callback: -99, Codes: [8]int{3, 4, 5, 6, 7, 8}})
	}
	return cases
}
