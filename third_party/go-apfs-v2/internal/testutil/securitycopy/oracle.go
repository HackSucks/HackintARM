// Package securitycopy shares native-oracle replay between tests and the
// qualification harness. It is never imported by production packages.
package securitycopy

import (
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

type Properties struct {
	UID, GID, Mode                    *uint32
	OwnerUUID, GroupUUID, RawSecurity *string
}
type Source struct {
	Properties     Properties
	UID, GID, Mode uint32
}
type Metadata struct {
	Properties            Properties
	UID, GID, Mode, Flags uint32
}
type Event struct {
	Operation        string
	NoSetID          bool
	Code, Errno      int
	UID, GID         uint32
	Mode             int32
	SecurityArgument aclmeta.DarwinSecurityArgument
	Security, ACL    *string
}
type Observation struct {
	Source                                   Source
	Cache                                    Properties
	Events                                   []Event
	Code, Errno                              int
	SourceBefore, SourceAfter, Before, After Metadata
	IdentityUnchanged, PayloadUnchanged      bool
	Filesystem                               string
}
type Case struct {
	Name, Kind, SourceACL, DestinationACL       string
	Flags, Filter, Presence, Fault, TargetFlags int
	Native                                      Observation
	QueryVolumes                                bool
	SourceVolume, DestinationVolume             int
}
type Fixture struct {
	Revision, Host, HelperSHA256, CopyfileSHA256, LibcSHA256 string
	Models, Applications                                     []Case
	Helpers                                                  map[string]string `json:",omitempty"`
}
type NativeError int

func (e NativeError) Error() string { return fmt.Sprintf("native errno %d", e) }
func Decode(v *string) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	return hex.DecodeString(*v)
}
func Encode(b []byte) *string {
	if b == nil {
		return nil
	}
	s := hex.EncodeToString(b)
	return &s
}
func ACL(v *string) (*appledouble.ACL, error) {
	b, e := Decode(v)
	if e != nil || b == nil {
		return nil, e
	}
	return appledouble.ParseACLBinary(b)
}
func ACLBytes(a *appledouble.ACL) *string {
	if a == nil {
		return nil
	}
	b, e := a.MarshalBinary()
	if e != nil {
		panic(e)
	}
	return Encode(b)
}
func (p Properties) Go() (aclmeta.DarwinChmodProperties, error) {
	out := aclmeta.DarwinChmodProperties{UID: p.UID, GID: p.GID, Mode: p.Mode}
	for _, pair := range []struct {
		in  *string
		out **[16]byte
	}{{p.OwnerUUID, &out.OwnerUUID}, {p.GroupUUID, &out.GroupUUID}} {
		if pair.in != nil {
			b, e := Decode(pair.in)
			if e != nil || len(b) != 16 {
				return out, fmt.Errorf("UUID input")
			}
			v := [16]byte(b)
			*pair.out = &v
		}
	}
	if p.RawSecurity != nil {
		b, e := Decode(p.RawSecurity)
		if e != nil {
			return out, e
		}
		out.RawSecurity, e = appledouble.ParseDarwinFileSecurity(b)
		if e != nil {
			return out, e
		}
	}
	return out, nil
}
func PropertiesFromGo(p aclmeta.DarwinChmodProperties) Properties {
	out := Properties{UID: p.UID, GID: p.GID, Mode: p.Mode}
	if p.OwnerUUID != nil {
		out.OwnerUUID = Encode(p.OwnerUUID[:])
	}
	if p.GroupUUID != nil {
		out.GroupUUID = Encode(p.GroupUUID[:])
	}
	if p.RawSecurity != nil {
		b, e := p.RawSecurity.MarshalDarwinBinary()
		if e != nil {
			panic(e)
		}
		out.RawSecurity = Encode(b)
	}
	return out
}
func Options(flags, filter int) hostdata.SecurityCopyOptions {
	return hostdata.SecurityCopyOptions{ACL: flags&1 != 0, Stat: flags&2 != 0, ForbidCopySetID: filter == 1 || filter == 2, AlwaysCopySetID: filter == 2, SourceNoSetID: filter == 3, DestinationNoSetID: filter == 4}
}

type backend struct {
	want, got []Event
	mismatch  error
}

// NewBackend reuses the exact request/error recorder for source-acquisition
// integration qualification. It is test support, never a production adapter.
func NewBackend(want []Event) *backend { return &backend{want: want} }
func (b *backend) Events() []Event     { return b.got }
func (b *backend) Mismatch() error     { return b.mismatch }

func (b *backend) record(e Event) error {
	i := len(b.got)
	if i >= len(b.want) {
		b.mismatch = fmt.Errorf("unexpected operation %s", e.Operation)
		return b.mismatch
	}
	w := b.want[i]
	e.Code, e.Errno = w.Code, w.Errno
	b.got = append(b.got, e)
	if !reflect.DeepEqual(e, w) {
		b.mismatch = fmt.Errorf("event %d mismatch: got %+v want %+v", i, e, w)
		return b.mismatch
	}
	if e.Code != 0 {
		return NativeError(e.Errno)
	}
	return nil
}
func (b *backend) CaptureDestinationACL() (*appledouble.ACL, error) {
	i := len(b.got)
	if i >= len(b.want) {
		return nil, b.record(Event{Operation: "capture"})
	}
	a, e := ACL(b.want[i].ACL)
	if e != nil {
		return nil, e
	}
	return a, b.record(Event{Operation: "capture", ACL: ACLBytes(a)})
}
func (b *backend) WriteSecurity(a aclmeta.DarwinChmodArguments) error {
	return b.record(Event{Operation: "security", UID: a.UID, GID: a.GID, Mode: a.Mode, SecurityArgument: a.SecurityArgument, Security: Encode(a.Security)})
}
func (b *backend) Chmod(mode uint16) error {
	return b.record(Event{Operation: "mode", Mode: int32(mode)})
}
func (b *backend) Chown(uid, gid uint32) error {
	return b.record(Event{Operation: "ownership", UID: uid, GID: gid})
}
func (b *backend) SetACL(a *appledouble.ACL) error {
	return b.record(Event{Operation: "acl", ACL: ACLBytes(a)})
}

func (b *backend) NoSetID(volume hostdata.SecurityCopyVolume) (bool, error) {
	i := len(b.got)
	e := Event{Operation: "volume-" + string(volume)}
	if i < len(b.want) {
		e.NoSetID = b.want[i].NoSetID
	}
	err := b.record(e)
	return e.NoSetID, err
}

// Replay uses observed errors as backend responses and independently checks the
// Go executor's decisions and exact requests, including source-cache effects.
func Replay(tc Case) (hostdata.SecurityCopyResult, []Event, error) {
	n := tc.Native
	p, e := n.Source.Properties.Go()
	if e != nil {
		return hostdata.SecurityCopyResult{}, nil, e
	}
	b := &backend{want: n.Events}
	options := Options(tc.Flags, tc.Filter)
	if tc.QueryVolumes {
		options.VolumePolicy = b
	}
	result, runErr := hostdata.CopySecurity(hostdata.SecurityCopySource{Properties: p, UID: n.Source.UID, GID: n.Source.GID, Mode: n.Source.Mode}, options, b)
	if b.mismatch != nil {
		return result, b.got, b.mismatch
	}
	if !reflect.DeepEqual(b.got, n.Events) || (runErr != nil) != (n.Code != 0) || result.Completed != (n.Code == 0) {
		return result, b.got, fmt.Errorf("outcome/order mismatch: %v", runErr)
	}
	if n.Code != 0 {
		want := error(NativeError(n.Errno))
		if n.Errno == 12 {
			want = appledouble.ErrACLCopy
		}
		if !errors.Is(runErr, want) {
			return result, b.got, fmt.Errorf("fatal error cause mismatch: %v", runErr)
		}
	}
	if !reflect.DeepEqual(PropertiesFromGo(result.Source.Properties), n.Cache) {
		return result, b.got, fmt.Errorf("source cache mismatch: got %+v want %+v", PropertiesFromGo(result.Source.Properties), n.Cache)
	}
	writes := 0
	fallback := false
	var failures []hostdata.SecurityCopyFailure
	var queries []hostdata.SecurityCopyVolumeQuery
	for _, v := range n.Events {
		if strings.HasPrefix(v.Operation, "volume-") {
			q := hostdata.SecurityCopyVolumeQuery{Volume: hostdata.SecurityCopyVolume(strings.TrimPrefix(v.Operation, "volume-")), NoSetID: v.NoSetID}
			if v.Code != 0 {
				q.NoSetID, q.Err = false, NativeError(v.Errno)
			}
			queries = append(queries, q)
		} else if v.Operation != "capture" {
			writes++
			if v.Operation == "security" && v.Code != 0 {
				fallback = true
			}
			if v.Code != 0 {
				failures = append(failures, hostdata.SecurityCopyFailure{Operation: v.Operation, Err: NativeError(v.Errno)})
			}
		}
	}
	if !reflect.DeepEqual(result.VolumeQueries, queries) {
		return result, b.got, fmt.Errorf("volume diagnostics mismatch")
	}
	if result.Writes != writes || result.Fallback != fallback || !reflect.DeepEqual(result.Failures, failures) {
		return result, b.got, fmt.Errorf("write diagnostics mismatch")
	}
	return result, b.got, nil
}
func Protocol(events []Event) string {
	var b strings.Builder
	for _, e := range events {
		switch e.Operation {
		case "volume-source", "volume-destination":
			fmt.Fprintln(&b, e.Operation)
		case "capture":
			fmt.Fprintln(&b, "capture")
		case "security":
			s := "-"
			if e.Security != nil {
				s = *e.Security
			}
			fmt.Fprintf(&b, "security %d %d %d %d %s\n", e.UID, e.GID, e.Mode, e.SecurityArgument, s)
		case "mode":
			fmt.Fprintf(&b, "mode %d\n", e.Mode)
		case "ownership":
			fmt.Fprintf(&b, "ownership %d %d\n", e.UID, e.GID)
		case "acl":
			fmt.Fprintf(&b, "acl %s\n", *e.ACL)
		default:
			panic("unknown operation")
		}
	}
	return b.String()
}
