// Package xattrrestore replays native ordinary-unpack xattr observations.
package xattrrestore

import (
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

type Event struct {
	Kind, Name string
	Code       int
	Copied     uint64
}
type Observation struct {
	Events                   []Event
	Code, StateError, Errno  int
	Copied                   uint64
	CallbackCleared, Present bool
	Stored                   string
}
type Case struct {
	Name, Attr          string
	Intent              uint32
	Sandboxed, Callback bool
	WriteError          int
	Actions             [3]int
	Length              int
	Initial             uint64
	Native              Observation
}
type Fixture struct {
	Revision, Host, HelperSHA256, CopyfileSHA256, PolicySHA256, HeaderSHA256 string
	Cases, Live                                                              []Case
}
type NativeError int

func (e NativeError) Error() string { return fmt.Sprintf("Darwin errno %d", int(e)) }
func WriteError(code int) error {
	if code == 0 {
		return nil
	}
	e := error(NativeError(code))
	if code == 1 {
		e = errors.Join(hostdata.ErrXattrRestoreNotPermitted, e)
	}
	return e
}
func Value(n int) []byte {
	v := make([]byte, n)
	for i := range v {
		v[i] = byte(i)
	}
	return v
}
func Replay(c Case, live bool) error {
	events := []Event{}
	options := hostdata.XattrRestoreOptions{CopyIntent: c.Intent, Sandboxed: c.Sandboxed, InitialCopied: c.Initial}
	if c.Callback {
		options.Callback = func(n hostdata.XattrRestoreNotice) hostdata.CopyPipelineAction {
			i := 0
			if n.Event == hostdata.XattrRestoreError {
				i = 1
			}
			if n.Event == hostdata.XattrRestoreFinish {
				i = 2
			}
			events = append(events, Event{Kind: string(n.Event), Name: n.Name, Code: c.Actions[i], Copied: n.Copied})
			return hostdata.CopyPipelineAction(c.Actions[i])
		}
	}
	writeCode := c.WriteError
	if live {
		for _, e := range c.Native.Events {
			if e.Kind == "write" {
				writeCode = e.Code
			}
		}
	}
	var stored []byte
	r, err := hostdata.RestoreXattr(c.Attr, Value(c.Length), options, func(name string, v []byte) error {
		if name != c.Attr || !reflect.DeepEqual(v, Value(c.Length)) {
			panic("write request mismatch")
		}
		events = append(events, Event{Kind: "write", Name: name, Code: writeCode})
		if writeCode == 0 {
			stored = v
		}
		return WriteError(writeCode)
	})
	wrote, applied := false, false
	for _, e := range c.Native.Events {
		if e.Kind == "write" {
			wrote = true
			applied = e.Code == 0
		}
	}
	selected := len(c.Native.Events) > 0
	if !reflect.DeepEqual(events, c.Native.Events) || r.Completed != (c.Native.Code == 0) || r.Copied != c.Native.Copied || r.Selected != selected || r.Applied != applied || (err != nil) != (c.Native.Code != 0) || !c.Native.CallbackCleared {
		return fmt.Errorf("%s: result %+v error %v events %+v; native %+v", c.Name, r, err, events, c.Native)
	}
	if wrote && !errors.Is(r.WriteError, NativeError(writeCode)) && writeCode != 0 {
		return fmt.Errorf("lost write error")
	}
	if c.Native.StateError == 89 && !errors.Is(err, hostdata.ErrXattrRestoreCanceled) {
		return fmt.Errorf("lost cancellation")
	}
	if live && ((r.Applied && !(c.Attr == hostdata.ResourceForkName && c.Length == 0)) != c.Native.Present || hex.EncodeToString(stored) != c.Native.Stored) {
		return fmt.Errorf("native stored value mismatch: %s", c.Name)
	}
	return nil
}
func Cases() []Case {
	var out []Case
	add := func(c Case) { c.Name = fmt.Sprintf("model-%04d", len(out)); out = append(out, c) }
	names := []string{"org.example.value", "org.example.value#N", "org.example.value#Nn", "org.example.value#nN", "org.example.value#", "org.example.value#N#", "org.example.value#N#n", "org.example.value#PCSBNx", "org.example.value#nNPCSB", "org.example.value#?n", "com.apple.security.secret", "com.apple.security.secret#", "com.apple.security.secret#N", "com.apple.security.secret#n", "com.apple.security", "com.apple.Security.secret", "com.apple.root.installed", "com.apple.root.installed#N", "com.apple.TextEncoding", "com.apple.metadata:kMDItemOwnerName", "com.apple.FinderInfo", "com.apple.ResourceFork"}
	for _, name := range names {
		for _, intent := range []uint32{0, 1, 2, 3, 4, 5, ^uint32(0)} {
			for _, sandbox := range []bool{false, true} {
				add(Case{Attr: name, Intent: intent, Sandboxed: sandbox, Callback: true, Length: 7, Initial: 77})
			}
		}
	}
	for _, name := range []string{"org.example.value", "com.apple.root.installed", "com.apple.root.installed#"} {
		for _, code := range []int{0, 1, 13, 5, 45} {
			for _, size := range []int{0, 7} {
				add(Case{Attr: name, WriteError: code, Length: size, Initial: 77})
				for _, start := range []int{-1, 0, 1, 2, 3} {
					for _, err := range []int{-1, 0, 1, 2, 3} {
						for _, finish := range []int{-1, 0, 1, 2, 3} {
							add(Case{Attr: name, WriteError: code, Length: size, Initial: 77, Callback: true, Actions: [3]int{start, err, finish}})
						}
					}
				}
			}
		}
	}
	return out
}
func LiveCases() []Case {
	var out []Case
	for _, name := range []string{"org.example.restore", "org.example.restore#N", "org.example.restore#Nn", "com.apple.root.installed", "com.apple.FinderInfo", "com.apple.ResourceFork"} {
		for _, size := range []int{0, 7, 32} {
			for _, cb := range []bool{false, true} {
				for _, actions := range [][3]int{{0, 0, 0}, {1, 1, 1}, {2, 2, 2}, {0, 2, 0}, {0, 0, 2}} {
					out = append(out, Case{Name: fmt.Sprintf("live-%03d", len(out)), Attr: name, Length: size, Initial: 77, Callback: cb, Actions: actions})
				}
			}
		}
	}
	return out
}
