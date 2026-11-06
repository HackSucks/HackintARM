// Package packnative compares packing with independently executed Apple bodies.
package packnative

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

type Event struct {
	Kind, Name    string
	Count, Offset int64
	Code          int
	Copied        uint64
}
type Observation struct {
	Events           []Event
	Code, StateError int
	Copied           uint64
	CallbackCleared  bool
	OutputSHA256     string
	OutputLength     int
}
type Case struct {
	Scenario                                   int
	OrdinarySize, ForkSize                     int64
	ListError, QueryKind, QueryError           int
	ReadKind, ReadDelta, WriteFail, WriteShort int
	Callback                                   bool
	Actions                                    [4]int
	ACLPresent, Quarantine, Intent, Filtered   int
	StatCode                                   int
	Native                                     Observation
}
type Fixture struct {
	Revision, Host, HelperSHA256, SourceSHA256 string
	Cases                                      []Case
}

func Cases() []Case {
	var cases []Case
	base := func(scenario int) Case { return Case{Scenario: scenario, OrdinarySize: 3, ForkSize: 4} }
	for _, scenario := range []int{0, 1, 2, 3, 4, 6, 7, 8} {
		cases = append(cases, base(scenario))
	}
	for _, scenario := range []int{1, 2, 3, 4} {
		for a := range 3 {
			for b := range 3 {
				for c := range 3 {
					for d := range 3 {
						v := base(scenario)
						v.Callback, v.Actions = true, [4]int{a, b, c, d}
						cases = append(cases, v)
					}
				}
			}
		}
	}
	for _, scenario := range []int{1, 2, 3, 4} {
		for _, callback := range []bool{false, true} {
			for mode := range 8 {
				v := base(scenario)
				v.Callback = callback
				switch mode {
				case 0:
					v.ListError = 5
				case 1:
					v.QueryKind, v.QueryError = 1, 5
				case 2:
					v.QueryKind, v.QueryError = 3, 5
				case 3:
					v.ReadKind, v.ReadDelta = 1, -1
				case 4:
					v.ReadKind, v.ReadDelta = 2, -1
				case 5:
					v.ReadKind, v.ReadDelta = 3, -1
				case 6:
					v.WriteFail = 1
				case 7:
					v.WriteShort = 1
				}
				cases = append(cases, v)
			}
		}
	}
	for _, size := range []int64{0, 16 << 20, 16<<20 + 1} {
		v := base(1)
		v.OrdinarySize = size
		cases = append(cases, v)
	}
	for _, size := range []int64{0, 2147483648} {
		for _, cb := range []bool{false, true} {
			v := base(3)
			v.ForkSize, v.Callback = size, cb
			cases = append(cases, v)
		}
	}
	for _, present := range []int{-1, 1} {
		for _, scenario := range []int{0, 1, 4} {
			v := base(scenario)
			v.ACLPresent = present
			cases = append(cases, v)
		}
	}
	for _, scenario := range []int{0, 1, 6, 7} {
		v := base(scenario)
		v.Quarantine = 1
		cases = append(cases, v)
	}
	for _, filter := range []int{0, 1} {
		v := base(8)
		v.Intent, v.Filtered = 1, filter
		cases = append(cases, v)
	}
	for _, code := range []int{-1, 1} {
		v := base(1)
		v.StatCode = code
		cases = append(cases, v)
	}
	return cases
}

func Input(c Case) string {
	callback := 0
	if c.Callback {
		callback = 1
	}
	return fmt.Sprintf("%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n", c.Scenario, c.OrdinarySize, c.ForkSize, c.ListError, c.QueryKind, c.QueryError, c.ReadKind, c.ReadDelta, c.WriteFail, c.WriteShort, callback, c.Actions[0], c.Actions[1], c.Actions[2], c.Actions[3], c.ACLPresent, c.Quarantine, c.Intent, c.Filtered, c.StatCode)
}

type backend struct {
	c      Case
	events []Event
	output []byte
	writes int
}

func (b *backend) event(kind, name string, count, offset int64, code int, copied uint64) {
	b.events = append(b.events, Event{kind, name, count, offset, code, copied})
}
func diagnostic(n int) error {
	if n == 0 {
		return nil
	}
	return fmt.Errorf("native %d", n)
}
func (b *backend) ACLPresent() (bool, error) {
	code := 0
	if b.c.ACLPresent <= 0 {
		code = 2
	}
	b.event("acl-probe", "", 0, 0, code, 0)
	return code == 0, diagnostic(code)
}
func (b *backend) Names(capacity int) ([]string, error) {
	b.event("list", "", int64(capacity), 0, b.c.ListError, 0)
	if b.c.ListError != 0 {
		return nil, diagnostic(b.c.ListError)
	}
	switch b.c.Scenario {
	case 1, 7:
		return []string{"user.z", "user.a"}, nil
	case 2:
		return []string{appledouble.FinderInfoName}, nil
	case 3:
		return []string{appledouble.ResourceForkName}, nil
	case 4:
		return []string{"user.z", appledouble.ResourceForkName, appledouble.FinderInfoName, "user.a"}, nil
	case 6:
		return []string{appledouble.QuarantineName}, nil
	case 8:
		return []string{"skip#N", "user.a"}, nil
	}
	return nil, nil
}
func (b *backend) PreserveForIntent(name string, intent uint32) bool {
	selected := 1
	if b.c.Filtered != 0 && name == "skip#N" {
		selected = 0
	}
	b.event("intent", name, int64(intent), 0, selected, 0)
	return selected != 0
}
func kind(name string) int {
	if name == appledouble.FinderInfoName {
		return 2
	}
	if name == appledouble.ResourceForkName {
		return 3
	}
	return 1
}
func (b *backend) size(name string) int64 {
	switch kind(name) {
	case 2:
		return 32
	case 3:
		return b.c.ForkSize
	}
	return b.c.OrdinarySize
}
func (b *backend) XattrSize(name string) (int64, error) {
	size := b.size(name)
	code := 0
	if kind(name) == b.c.QueryKind {
		code = b.c.QueryError
	}
	b.event("size", name, size, 0, code, 0)
	return size, diagnostic(code)
}
func (b *backend) ReadXattr(name string, dst []byte) (int, error) {
	size := b.size(name)
	if kind(name) == b.c.ReadKind {
		size += int64(b.c.ReadDelta)
	}
	if size < 0 || size > int64(len(dst)) {
		code := 34
		if size < 0 {
			code = 5
		}
		b.event("read", name, int64(len(dst)), 0, code, 0)
		return 0, diagnostic(code)
	}
	for i := int64(0); i < size; i++ {
		dst[i] = byte('A' + i%7)
	}
	b.event("read", name, int64(len(dst)), 0, int(size), 0)
	return int(size), nil
}
func (b *backend) ACL() ([]byte, error) {
	b.event("acl", "", 4, 0, 0, 0)
	return []byte("acl\x00"), nil
}
func (b *backend) Quarantine() ([]byte, error) {
	b.event("quarantine", "", 4, 0, 0, 0)
	return []byte("q/01"), nil
}
func (b *backend) WriteAt(data []byte, offset int64) (int, error) {
	b.writes++
	n := len(data)
	if b.writes == b.c.WriteFail {
		b.event("write", "", int64(n), offset, -1, 0)
		return 0, diagnostic(5)
	}
	if b.writes == b.c.WriteShort && n > 0 {
		n--
	}
	b.event("write", "", int64(len(data)), offset, n, 0)
	end := int(offset) + n
	if end > len(b.output) {
		b.output = append(b.output, make([]byte, end-len(b.output))...)
	}
	copy(b.output[int(offset):end], data[:n])
	return n, nil
}
func (b *backend) Stat() hostdata.CopyStageResult {
	b.event("stat", "", 0, 0, b.c.StatCode, 0)
	return hostdata.CopyStageResult{Code: b.c.StatCode, Err: diagnostic(b.c.StatCode)}
}

func Replay(c Case) error {
	b := &backend{c: c}
	opts := hostdata.PackOptions{CopyACL: c.ACLPresent != 0, HasQuarantine: c.Quarantine != 0, CopyIntent: uint32(c.Intent), InitialCopied: 77, Limits: appledouble.DefaultStreamLimits(), MaxActiveBytes: 64 << 20}
	if c.Callback {
		opts.Callback = func(n hostdata.PackNotice) hostdata.CopyPipelineAction {
			index := map[hostdata.PackEvent]int{hostdata.PackStart: 0, hostdata.PackProgress: 1, hostdata.PackFinish: 2, hostdata.PackError: 3}[n.Event]
			action := c.Actions[index]
			b.event(string(n.Event), n.Name, 0, 0, action, n.Copied)
			return hostdata.CopyPipelineAction(action)
		}
	}
	result, err := hostdata.PackAppleDouble(context.Background(), opts, b)
	if !reflect.DeepEqual(b.events, c.Native.Events) {
		return fmt.Errorf("events mismatch\nGo: %+v\nC: %+v", b.events, c.Native.Events)
	}
	if result.Code != c.Native.Code || result.Copied != c.Native.Copied {
		return fmt.Errorf("result %+v vs native %+v", result, c.Native)
	}
	if !c.Native.CallbackCleared {
		return errors.New("native callback pointer retained")
	}
	if result.Code == 0 && err != nil {
		return err
	}
	if len(b.output) != c.Native.OutputLength || fmt.Sprintf("%x", sha256.Sum256(b.output)) != c.Native.OutputSHA256 {
		return fmt.Errorf("output bytes mismatch (%d vs %d)", len(b.output), c.Native.OutputLength)
	}
	return nil
}
