// Package unpackrestore replays complete Apple unpack observations.
package unpackrestore

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

type Event struct {
	Kind, Name string
	Code       int
	Copied     int64
	Value      string
}
type Observation struct {
	VerifiedWrites             int
	RemovedSeeds               bool
	Events                     []Event
	Code, StateError           int
	Copied                     uint64
	Invisible, CallbackCleared bool
}
type Case struct {
	Image, List, Remove, Ordinary, Finder, Fork, ForkStat, Times, Quarantine, ACL, Stat int
	StatFlag, Callback                                                                  bool
	Actions                                                                             [3]int
	Target                                                                              int
	Directory                                                                           bool
	Intent                                                                              uint32
	Native                                                                              Observation
}
type Fixture struct {
	Revision, Host, HelperSHA256, CopyfileSHA256, PolicySHA256, HeaderSHA256 string
	Images                                                                   []string
	Cases, Live                                                              []Case
}

func Images() []string {
	fork := make([]byte, 286)
	for _, i := range []int{0, 4, 256, 260} {
		binary.BigEndian.PutUint32(fork[i:], 256)
	}
	for _, i := range []int{12, 268} {
		binary.BigEndian.PutUint32(fork[i:], 30)
	}
	copy(fork[16:], "This resource fork intentionally left blank   ")
	copy(fork[280:], []byte{0, 28, 0, 30, 255, 255})
	finder := [32]byte{0: 1, 8: 0x40}
	attrs := []appledouble.Attr{{Name: "a", Value: []byte{1, 2}}, {Name: appledouble.ACLTextName, Value: []byte("first")}, {Name: appledouble.ACLTextName, Value: []byte("last")}, {Name: appledouble.ACLTextName}, {Name: appledouble.QuarantineName, Value: []byte("q/01")}, {Name: appledouble.QuarantineName}, {Name: "com.apple.root.installed", Value: []byte{3}}, {Name: "z#N", Value: []byte{4}}}
	files := []appledouble.File{{}, {Attrs: attrs, FinderInfo: finder, ResourceFork: []byte{9, 8, 7}}, {FinderInfo: finder}, {ResourceFork: []byte{9, 8, 7}}, {ResourceFork: fork}, {Attrs: []appledouble.Attr{{Name: "empty"}, {Name: "present", Value: []byte{42}}}}, {Attrs: attrs}, {Attrs: []appledouble.Attr{{Name: appledouble.FinderInfoName, Value: finder[:]}, {Name: appledouble.ResourceForkName, Value: []byte{5}}, {Name: "z", Value: []byte{7}}}, FinderInfo: finder, ResourceFork: []byte{9, 8, 7}}}
	out := make([]string, 0, len(files)+1)
	for i := range files {
		b, e := files[i].Encode()
		if e != nil {
			panic(e)
		}
		out = append(out, hex.EncodeToString(b))
	}
	// Reverse actual table records without moving payloads to qualify wire order.
	b, _ := hex.DecodeString(out[1])
	count := int(binary.BigEndian.Uint16(b[118:]))
	off := 120
	var chunks [][]byte
	for range count {
		n := (11 + int(b[off+10]) + 3) &^ 3
		chunks = append(chunks, bytes.Clone(b[off:off+n]))
		off += n
	}
	pos := 120
	for i := len(chunks) - 1; i >= 0; i-- {
		pos += copy(b[pos:], chunks[i])
	}
	out = append(out, hex.EncodeToString(b))
	return out
}
func Cases() []Case {
	var out []Case
	add := func(c Case) { out = append(out, c) }
	for img := range Images() {
		for list := 0; list < 8; list++ {
			for _, stat := range []bool{false, true} {
				add(Case{Image: img, List: list, StatFlag: stat, Remove: 5})
			}
		}
	}
	for _, img := range []int{1, 2, 3, 4, 7, 8} {
		for _, cb := range []bool{false, true} {
			for _, dir := range []bool{false, true} {
				for _, field := range []string{"ordinary", "finder", "fork", "fork-stat", "times", "quarantine", "acl", "stat"} {
					for _, code := range []int{-2, -1, 0, 1, 5, 13, 45} {
						c := Case{Image: img, List: 1, Callback: cb, Directory: dir, StatFlag: field == "stat"}
						switch field {
						case "ordinary":
							c.Ordinary = abs(code)
						case "finder":
							c.Finder = abs(code)
						case "fork":
							c.Fork = abs(code)
						case "fork-stat":
							c.ForkStat = abs(code)
						case "times":
							c.Times = abs(code)
						case "quarantine":
							c.Quarantine = code
						case "acl":
							c.ACL = code
						case "stat":
							c.Stat = code
						}
						add(c)
					}
				}
			}
		}
	}
	for _, target := range []int{1, 2, 3} {
		for _, writeErr := range []int{0, 5} {
			for _, a := range []int{0, 1, 2, 9} {
				for _, b := range []int{0, 1, 2, 9} {
					for _, d := range []int{0, 1, 2, 9} {
						c := Case{Image: 1, Callback: true, Target: target, Actions: [3]int{a, b, d}}
						switch target {
						case 1:
							c.Ordinary = writeErr
						case 2:
							c.Finder = writeErr
						case 3:
							c.Fork = writeErr
						}
						add(c)
					}
				}
			}
		}
	}
	// Fork failure masking and ACL return-code asymmetry (-1 alone stops).
	for _, acl := range []int{-2, -1, 0, 1} {
		for _, stat := range []int{-2, -1, 0, 1} {
			for _, selected := range []bool{false, true} {
				add(Case{Image: 1, Fork: 5, ACL: acl, Stat: stat, StatFlag: selected})
			}
		}
	}
	for _, intent := range []uint32{0, 1, ^uint32(0)} {
		add(Case{Image: 1, Intent: intent, Callback: true})
	}
	return out
}
func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
func LiveCases() []Case {
	var out []Case
	for _, img := range []int{0, 2, 3, 4, 5, 7} {
		for _, dir := range []bool{false, true} {
			for _, cb := range []bool{false, true} {
				for _, action := range [][3]int{{0, 0, 0}, {1, 0, 0}, {2, 0, 0}, {0, 0, 2}} {
					out = append(out, Case{Image: img, Directory: dir, Callback: cb, Actions: action})
				}
			}
		}
	}
	return out
}

type replay struct {
	c      Case
	events []Event
	pos    int
	err    error
}

func (r *replay) next(kind, name string, value []byte, copied uint64, checkCopied bool) Event {
	if r.pos >= len(r.events) {
		r.err = fmt.Errorf("extra Go operation %s", kind)
		return Event{Code: 5}
	}
	e := r.events[r.pos]
	r.pos++
	if e.Kind != kind || e.Name != name || e.Value != hex.EncodeToString(value) || (checkCopied && e.Copied != int64(copied)) {
		r.err = fmt.Errorf("operation %d: got %s/%s/%x/%d, native %+v", r.pos, kind, name, value, copied, e)
	}
	return e
}
func diagnostic(code int) error {
	if code == 0 {
		return nil
	}
	e := fmt.Errorf("native code %d", code)
	if code == 1 {
		return errors.Join(hostdata.ErrXattrRestoreNotPermitted, e)
	}
	if code == 45 {
		return errors.Join(hostdata.ErrXattrUnsupported, e)
	}
	return e
}
func (r *replay) ListXattrSize() (int, error) {
	e := r.next("list-size", "", nil, 0, false)
	if e.Code != 0 {
		return -1, diagnostic(e.Code)
	}
	return int(e.Copied), nil
}
func (r *replay) XattrNames(_ int) ([]string, error) {
	if r.pos >= len(r.events) {
		return nil, errors.New("missing list")
	}
	e := r.events[r.pos]
	if e.Kind == "list-allocation" {
		r.next("list-allocation", "", nil, 0, false)
		return nil, errors.Join(hostdata.ErrUnpackListAllocation, diagnostic(e.Code))
	}
	b, _ := hex.DecodeString(e.Value)
	r.next("list-names", "", b, 0, false)
	if e.Code != 0 {
		return nil, diagnostic(e.Code)
	}
	if len(b) == 0 {
		return nil, nil
	}
	return strings.Split(string(b[:len(b)-1]), "\x00"), nil
}
func (r *replay) RemoveXattr(n string) error {
	return diagnostic(r.next("remove", n, nil, 0, false).Code)
}
func (r *replay) WriteXattr(n string, v []byte) error {
	kind := "ordinary"
	if r.pos < len(r.events) {
		kind = r.events[r.pos].Kind
	}
	if kind != "ordinary" && kind != "finder-info" && kind != "resource-fork" {
		r.err = fmt.Errorf("unexpected write kind %s", kind)
	}
	return diagnostic(r.next(kind, n, v, 0, false).Code)
}
func (r *replay) CaptureForkState() (hostdata.UnpackForkState, error) {
	return hostdata.UnpackForkState{Directory: r.c.Directory}, diagnostic(r.next("fork-stat", "", nil, 0, false).Code)
}
func (r *replay) RestoreForkTimes(hostdata.UnpackForkState) error {
	return diagnostic(r.next("fork-times", "", nil, 0, false).Code)
}
func (r *replay) stage(s string, b []byte, copied uint64) hostdata.CopyStageResult {
	e := r.next(s, "", b, copied, true)
	return hostdata.CopyStageResult{Code: e.Code, Err: diagnostic(e.Code)}
}
func (r *replay) Quarantine(b []byte) hostdata.CopyStageResult { return r.stage("quarantine", b, 0) }
func (r *replay) ACL(b []byte) hostdata.CopyStageResult        { return r.stage("acl", b, 0) }
func (r *replay) Stat(invisible bool) hostdata.CopyStageResult {
	var n uint64
	if invisible {
		n = 1
	}
	return r.stage("stat", nil, n)
}
func Replay(c Case, images []string) error {
	return replayCase(c, images, false)
}

// ReplaySequential checks the same independently captured native observations
// with reads deferred until their native execution points.
func ReplaySequential(c Case, images []string) error {
	return replayCase(c, images, true)
}

func replayCase(c Case, images []string, sequential bool) error {
	b, e := hex.DecodeString(images[c.Image])
	if e != nil {
		return e
	}
	r := &replay{c: c, events: c.Native.Events}
	opts := hostdata.UnpackOptions{InitialCopied: 77, Stat: c.StatFlag, CopyIntent: c.Intent}
	if c.Callback {
		opts.Callback = func(n hostdata.UnpackNotice) hostdata.CopyPipelineAction {
			kind := string(n.Stage) + "-" + string(n.Event)
			e := r.next(kind, n.Name, nil, n.Copied, true)
			stage := map[hostdata.UnpackStage]int{hostdata.UnpackOrdinary: 1, hostdata.UnpackFinderInfo: 2, hostdata.UnpackResourceFork: 3}[n.Stage]
			index := map[hostdata.XattrRestoreEvent]int{hostdata.XattrRestoreStart: 0, hostdata.XattrRestoreError: 1, hostdata.XattrRestoreFinish: 2}[n.Event]
			action := 0
			if c.Target == 0 || c.Target == stage {
				action = c.Actions[index]
			}
			if e.Code != action {
				r.err = fmt.Errorf("callback action %d != native %d", action, e.Code)
			}
			return hostdata.CopyPipelineAction(action)
		}
	}
	var got hostdata.UnpackResult
	var err error
	if sequential {
		got, err = hostdata.RestoreAppleDoubleSequential(context.Background(), bytes.NewReader(b), hostdata.UnpackSequentialOptions{
			UnpackOptions: opts, Limits: appledouble.DefaultStreamLimits(), MaxActiveBytes: 1 << 20,
		}, r)
	} else {
		got, err = hostdata.RestoreAppleDouble(b, opts, r)
	}
	if r.err != nil {
		return r.err
	}
	if r.pos != len(r.events) {
		return fmt.Errorf("unconsumed native events %d/%d", r.pos, len(r.events))
	}
	if !reflect.DeepEqual([]any{got.Code, got.Copied, got.MakeInvisible}, []any{c.Native.Code, c.Native.Copied, c.Native.Invisible}) {
		return fmt.Errorf("result %+v vs %+v", got, c.Native)
	}
	if !c.Native.CallbackCleared {
		return errors.New("native callback leak")
	}
	if c.Native.StateError == 89 && !errors.Is(err, hostdata.ErrXattrRestoreCanceled) {
		return fmt.Errorf("missing cancellation: %v", err)
	}
	if c.Native.Code == 0 && err != nil {
		return err
	}
	return nil
}
