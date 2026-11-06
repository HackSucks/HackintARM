package hostdata

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"sort"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// PackBackend binds source metadata and positioned destination writes to held
// objects. Names returns the complete native list fitting capacity (including
// NUL terminators), in native order. ReadXattr is a single native-style read;
// XattrSize is the separate size query. ACL/Quarantine return owned serialized
// records, not filesystem xattr forms. ACL includes its terminating NUL.
// PreserveForIntent uses captured target policy, never the running Go host.
// No operation may reopen an endpoint pathname or conceal a read failure.
type PackBackend interface {
	ACLPresent() (bool, error)
	Names(capacity int) ([]string, error)
	PreserveForIntent(name string, intent uint32) bool
	XattrSize(name string) (int64, error)
	ReadXattr(name string, dst []byte) (int, error)
	ACL() ([]byte, error)
	Quarantine() ([]byte, error)
	WriteAt(data []byte, offset int64) (int, error)
	Stat() CopyStageResult
}

// PackEvent identifies native packing callback positions. Start callbacks for
// ordinary records all precede their data reads. A Progress Skip cannot remove
// a record whose header has already been laid out.
type PackEvent string

const (
	PackStart    PackEvent = "start"
	PackProgress PackEvent = "progress"
	PackFinish   PackEvent = "finish"
	PackError    PackEvent = "error"
)

// PackNotice preserves the native callback's current name and progress value.
// Name can be empty on resource-fork errors after native clears xattr_name.
type PackNotice struct {
	Event  PackEvent
	Name   string
	Copied uint64
}

// PackOptions explicitly selects native-compatible packing. This operation may
// lose values that a lossless StreamFile.EncodeTo would retain. CopyACL probes
// captured ACL state. HasQuarantine means captured source quarantine is present.
// Xattrs are always enumerated; an empty source returns an empty list.
// Limits bound data/output work; MaxActiveBytes bounds the two native header/name
// buffers plus one value allocation. Zero means zero budget, never a default.
type PackOptions struct {
	CopyACL, HasQuarantine bool
	CopyIntent             uint32
	InitialCopied          uint64
	Limits                 appledouble.StreamLimits
	MaxActiveBytes         uint64
	Callback               func(PackNotice) CopyPipelineAction
}

// PackLoss records native behavior that does not preserve a source value.
// A zero native result does not imply this list is empty.
type PackLoss struct{ Name, Reason string }

// PackResult keeps native return/control flow separate from preservation.
// Data is written before the header. HeaderWritten does not imply all preceding
// writes succeeded, and destination suffix bytes are never implicitly truncated.
type PackResult struct {
	Code          int
	Copied        uint64
	HeaderWritten bool
	Failures      []UnpackFailure
	Losses        []PackLoss
}

var (
	ErrPackAllocation = errors.New("AppleDouble packing allocation refused")
	ErrPackCanceled   = errors.New("AppleDouble packing callback canceled")
	// ErrPackUnsafe prevents undefined C memory behavior from becoming a Go
	// allocation, overflow, overread or fabricated successful preservation.
	ErrPackUnsafe = errors.New("AppleDouble native packing input has no safe defined representation")
)

type packExecution struct {
	ctx      context.Context
	backend  PackBackend
	options  PackOptions
	result   PackResult
	header   []byte
	names    []byte
	dataSize uint64
	total    uint64
	lastErr  error
}

// PackAppleDouble reproduces defined copyfile packing effects through held
// providers. Ordinary values above 16 MiB leave present empty records; forks
// above INT_MAX fail. Those are native policy outcomes, not codec limits.
// All failures/losses remain visible even when native control flow ignores or
// overwrites a code. Use StreamFile.EncodeTo for lossless canonical encoding.
// Context/IO errors and callbacks can leave partial positioned output. No source
// or destination is closed, removed, truncated or rolled back here.
func PackAppleDouble(ctx context.Context, options PackOptions, backend PackBackend) (PackResult, error) {
	s := &packExecution{ctx: ctx, options: options, backend: backend, result: PackResult{Copied: options.InitialCopied}}
	if ctx == nil || backend == nil {
		s.result.Code = -1
		return s.result, fs.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		s.result.Code = -1
		return s.result, err
	}
	if options.MaxActiveBytes < 2*appledouble.MaxHeader {
		s.result.Code = -1
		return s.result, errors.Join(ErrPackAllocation, appledouble.ErrStreamBudget)
	}
	s.header, s.names = make([]byte, appledouble.MaxHeader), make([]byte, appledouble.MaxHeader)
	s.put32(0, 0x00051607)
	s.put32(4, 0x00020000)
	copy(s.header[8:], "Mac OS X        ")
	binary.BigEndian.PutUint16(s.header[24:], 2)
	s.put32(26, 9)
	s.put32(30, 50)
	s.put32(34, 32)
	s.put32(38, 2)
	s.put32(42, 82)
	copy(s.header[84:], "ATTR")
	s.put32(96, 120)
	if err := s.execute(); err != nil {
		s.result.Code = -1
		return s.result, err
	}
	if s.result.Code != 0 {
		if s.lastErr != nil {
			return s.result, s.lastErr
		}
		return s.result, fmt.Errorf("AppleDouble packing returned %d", s.result.Code)
	}
	return s.result, nil
}

func (s *packExecution) fail(operation, name string, err error) {
	if err != nil {
		s.result.Failures = append(s.result.Failures, UnpackFailure{operation, name, err})
		s.lastErr = err
	}
}

func (s *packExecution) notify(event PackEvent, name string) CopyPipelineAction {
	if s.options.Callback == nil {
		return CopyPipelineContinue
	}
	return s.options.Callback(PackNotice{Event: event, Name: name, Copied: s.result.Copied})
}

func (s *packExecution) put32(off int, value uint32) {
	binary.BigEndian.PutUint32(s.header[off:], value)
}

func (s *packExecution) allocation(size uint64) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	l := s.options.Limits
	if size > uint64(math.MaxInt) || size > s.options.MaxActiveBytes-2*appledouble.MaxHeader || size > l.MaxValueBytes || s.total > l.MaxTotalValueBytes || size > l.MaxTotalValueBytes-s.total {
		return errors.Join(ErrPackAllocation, appledouble.ErrStreamBudget)
	}
	s.total += size
	return nil
}

func (s *packExecution) write(name string, data []byte, offset uint64) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if offset > s.options.Limits.MaxFileBytes || uint64(len(data)) > s.options.Limits.MaxFileBytes-offset {
		s.fail("write", name, appledouble.ErrStreamBudget)
		return appledouble.ErrStreamBudget
	}
	n, err := s.backend.WriteAt(data, int64(offset))
	if n < 0 || n > len(data) {
		err = ErrPackUnsafe
	} else if n != len(data) && err == nil {
		err = io.ErrShortWrite
	}
	s.fail("write", name, err)
	return err
}

func (s *packExecution) execute() error {
	prefix := 0
	if s.options.CopyACL {
		present, err := s.backend.ACLPresent()
		s.fail("acl-probe", appledouble.ACLTextName, err)
		if err == nil && present {
			prefix = copy(s.names, appledouble.ACLTextName) + 1
		}
	}
	names, err := s.backend.Names(appledouble.MaxHeader - prefix)
	s.fail("list", "", err)
	if err != nil {
		names = nil
	}
	end := prefix
	for _, name := range names {
		if name == "" || len(name) > 127 || strings.IndexByte(name, 0) >= 0 || len(name)+1 > len(s.names)-end {
			return ErrPackUnsafe
		}
		end += copy(s.names[end:], name) + 1
	}
	if len(names) != 0 {
		ordered := strings.Split(string(s.names[:end-1]), "\x00")
		sort.Strings(ordered)
		copy(s.names, strings.Join(ordered, "\x00")+"\x00")
	}
	entry, count := 120, 0
	seenQuarantine := false
	for off := 0; off < end; {
		name, next, err := s.nameAt(off)
		if err != nil {
			return err
		}
		if name == appledouble.FinderInfoName || name == appledouble.ResourceForkName {
			off = next
			continue
		}
		if name == appledouble.QuarantineName {
			seenQuarantine = true
		}
		selected := s.options.CopyIntent == 0 || s.backend.PreserveForIntent(name, s.options.CopyIntent)
		action := CopyPipelineSkip
		if selected {
			action = s.notify(PackStart, name)
		}
		if action == CopyPipelineQuit {
			return ErrPackCanceled
		}
		if action == CopyPipelineSkip {
			copy(s.names[off:], s.names[next:end])
			end -= next - off
			continue
		}
		length := (11 + len(name) + 1 + 3) &^ 3
		if entry+length >= len(s.header) {
			return appledouble.ErrTooLarge
		}
		s.header[entry+10] = byte(len(name) + 1)
		copy(s.header[entry+11:], name+"\x00")
		entry += length
		count++
		off = next
	}
	dataStart := uint64(entry)
	s.put32(96, uint32(dataStart))
	binary.BigEndian.PutUint16(s.header[118:], uint16(count))
	if s.options.HasQuarantine && !seenQuarantine {
		// The pinned native function overwrites this saved name-buffer offset;
		// it does not extend the data-pass bound or add a header record.
		copy(s.names[prefix:], appledouble.QuarantineName+"\x00")
		s.result.Losses = append(s.result.Losses, PackLoss{appledouble.QuarantineName, "captured quarantine has no listed record"})
	}
	hasFork := false
	entry = 120
	for off := 0; off < end; {
		name, next, err := s.nameAt(off)
		if err != nil {
			return err
		}
		off = next
		if name == appledouble.FinderInfoName {
			if err := s.finder(); err != nil {
				return err
			}
			continue
		}
		if name == appledouble.ResourceForkName {
			hasFork = true
			continue
		}
		value, skip, advance, err := s.value(name)
		if err != nil {
			return err
		}
		if entry > len(s.header)-12 {
			return ErrPackUnsafe
		}
		if !skip {
			if dataStart+s.dataSize > math.MaxUint32 || uint64(len(value)) > math.MaxUint32-dataStart-s.dataSize {
				return appledouble.ErrTooLarge
			}
			s.put32(entry, uint32(dataStart+s.dataSize))
			s.put32(entry+4, uint32(len(value)))
			if err := s.write(name, value, dataStart+s.dataSize); err != nil {
				s.result.Code = 1
			}
			s.dataSize += uint64(len(value))
		}
		if advance {
			entry += (11 + int(s.header[entry+10]) + 3) &^ 3
		}
	}
	attrEnd := dataStart + s.dataSize
	s.put32(100, uint32(s.dataSize))
	s.put32(42, uint32(attrEnd))
	s.put32(34, uint32(attrEnd-50))
	s.put32(92, uint32(attrEnd))
	if hasFork {
		code, err := s.fork(attrEnd)
		s.result.Code = code
		if err != nil {
			return err
		}
		if code != 0 {
			return s.lastErr
		}
	}
	if err := s.write("header", s.header[:int(dataStart)], 0); err != nil {
		s.result.Code = -1
		return err
	}
	s.result.HeaderWritten = true
	if s.result.Code == 0 {
		r := s.backend.Stat()
		s.result.Code = r.Code
		s.fail("stat", "", r.Err)
	}
	return nil
}

func (s *packExecution) nameAt(off int) (string, int, error) {
	if off < 0 || off >= len(s.names) {
		return "", 0, ErrPackUnsafe
	}
	n := bytes.IndexByte(s.names[off:], 0)
	if n < 0 {
		return "", 0, ErrPackUnsafe
	}
	return string(s.names[off : off+n]), off + n + 1, nil
}
