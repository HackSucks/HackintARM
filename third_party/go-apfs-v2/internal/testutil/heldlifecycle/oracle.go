// Package heldlifecycle replays unchanged native fcopyfile observations.
package heldlifecycle

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

type Event struct {
	Operation string
	Value     uint32
	Error     int
}
type Observation struct {
	Events      []Event
	Code, Errno int
	Mode        uint32
}
type Case struct {
	SourceMode, SourceError, FallbackError, Selected, Cached, Failures, StageCode int
	Native                                                                        Observation
}
type Fixture struct {
	Revision, Host, SourceSHA256, HelperSHA256 string
	Cases                                      []Case
}

func Cases() []Case {
	var out []Case
	for _, mode := range []int{0100644, 0040755, 0120777, 0010600} {
		for _, sourceError := range []int{0, 1, 45, 13} {
			for _, fallback := range []int{0, 5} {
				for selected := range 4 {
					for cached := range 2 {
						for _, code := range []int{-1, 0, 7} {
							out = append(out, Case{SourceMode: mode, SourceError: sourceError, FallbackError: fallback, Selected: selected, Cached: cached, StageCode: code})
						}
					}
				}
			}
		}
	}
	for failures := 1; failures < 32; failures++ {
		for selected := range 4 {
			for _, code := range []int{-1, 0, 7} {
				out = append(out, Case{SourceMode: 0100644, Failures: failures, Selected: selected, StageCode: code})
			}
		}
	}
	return out
}

type oracleError int

func (e oracleError) Error() string { return fmt.Sprintf("Darwin errno %d", e) }
func nativeError(n int) error {
	if n == 0 {
		return nil
	}
	return oracleError(n)
}

type endpoint struct {
	c      Case
	source bool
	mode   uint32
	writes int
	events *[]Event
}

func (e *endpoint) log(operation string, value uint32, code int) error {
	*e.events = append(*e.events, Event{operation, value, code})
	return nativeError(code)
}
func (e *endpoint) CaptureSecurity() (hostdata.SecurityCopySource, error) {
	result := hostdata.SecurityCopySource{UID: 501, GID: 20, Mode: uint32(e.c.SourceMode)}
	err := e.log("source-security", 0, e.c.SourceError)
	if e.c.SourceError == 1 {
		err = errors.Join(hostdata.ErrSecuritySourceNotPermitted, err)
	}
	if e.c.SourceError == 45 {
		err = errors.Join(hostdata.ErrSecuritySourceNotSupported, err)
	}
	return result, err
}
func (e *endpoint) CaptureStat() (hostdata.StatCopySource, error) {
	if e.source {
		return hostdata.StatCopySource{UID: 501, GID: 20, Mode: uint32(e.c.SourceMode)}, e.log("source-stat", 0, e.c.FallbackError)
	}
	return hostdata.StatCopySource{UID: 501, GID: 20, Mode: e.mode}, e.log("destination-stat", 0, 0)
}
func (e *endpoint) Chmod(mode uint16) error {
	mask := 1
	if e.writes > 0 {
		mask = 16
	}
	e.writes++
	code := 0
	if e.c.Failures&mask != 0 {
		code = 5
	}
	err := e.log("mode", uint32(mode), code)
	if err == nil {
		e.mode = e.mode&0170000 | uint32(mode)&^0170000
	}
	return err
}
func (e *endpoint) DisableCache() error {
	mask, name := 8, "destination-cache"
	if e.source {
		mask, name = 4, "source-cache"
	}
	code := 0
	if e.c.Failures&mask != 0 {
		code = 5
	}
	return e.log(name, 1, code)
}

func Replay(c Case) error {
	events := make([]Event, 0)
	source := &endpoint{c: c, source: true, events: &events}
	destination := &endpoint{c: c, mode: 0100400, events: &events}
	options := hostdata.HeldLifecycleOptions{Stat: c.Selected&1 != 0, NoCache: c.Selected&2 != 0}
	if c.Cached != 0 {
		options.SourceCache = &hostdata.SecurityCopySource{UID: 501, GID: 20, Mode: uint32(c.SourceMode)}
	}
	result, _ := hostdata.CopyHeldMetadata(source, destination, options, hostdata.HeldLifecycleStages{
		CaptureQuarantine: func() error {
			code := 0
			if c.Failures&2 != 0 {
				code = 5
			}
			return source.log("quarantine", 0, code)
		},
		Run: func(hostdata.SecurityCopySource) hostdata.CopyStageResult {
			code := 0
			if c.StageCode < 0 {
				code = 5
			}
			return hostdata.CopyStageResult{Code: c.StageCode, Err: source.log("route", 0, code)}
		},
	})
	// Ambient thread-local errno is retained as native evidence, not synthesized
	// from Go errors. Return/control flow, complete IO order and mode effects are
	// compared independently; ignored Go errors remain in result.Steps.
	if result.Code != c.Native.Code || destination.mode != c.Native.Mode || !reflect.DeepEqual(events, c.Native.Events) {
		return fmt.Errorf("native lifecycle mismatch: code=%d mode=%o events=%+v; native=%+v", result.Code, destination.mode, events, c.Native)
	}
	return nil
}
