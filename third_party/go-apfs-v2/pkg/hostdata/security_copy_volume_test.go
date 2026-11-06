package hostdata_test

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

type volumePolicyFunc func(hostdata.SecurityCopyVolume) (bool, error)

func (f volumePolicyFunc) NoSetID(v hostdata.SecurityCopyVolume) (bool, error) { return f(v) }

func TestSecurityCopyVolumePolicy(t *testing.T) {
	failure := errors.New("volume unavailable")
	states := []struct {
		value bool
		err   error
	}{{false, nil}, {true, nil}, {false, failure}, {true, failure}}
	for flags := 0; flags < 4; flags++ {
		for override := 0; override < 4; override++ {
			for si, sourceState := range states {
				for di, destinationState := range states {
					t.Run(fmt.Sprintf("f%d-o%d-s%d-d%d", flags, override, si, di), func(t *testing.T) {
						mode := uint32(0106755)
						source := hostdata.SecurityCopySource{Mode: 0106711, Properties: aclmeta.DarwinChmodProperties{Mode: &mode}}
						options := hostdata.SecurityCopyOptions{ACL: flags&1 != 0, Stat: flags&2 != 0, AlwaysCopySetID: override&1 != 0, ForbidCopySetID: override&2 != 0}
						var events []string
						options.VolumePolicy = volumePolicyFunc(func(v hostdata.SecurityCopyVolume) (bool, error) {
							events = append(events, string(v))
							if v == hostdata.SecurityCopySourceVolume {
								return sourceState.value, sourceState.err
							}
							if v != hostdata.SecurityCopyDestinationVolume {
								t.Fatal(v)
							}
							return destinationState.value, destinationState.err
						})
						var gotMode int32
						backend := copyBackend{
							capture: func() (*appledouble.ACL, error) { events = append(events, "capture"); return nil, nil },
							mode:    func(m uint16) error { events = append(events, "mode"); gotMode = int32(m); return nil },
							security: func(a aclmeta.DarwinChmodArguments) error {
								events = append(events, "security")
								gotMode = a.Mode
								return nil
							},
						}
						result, err := hostdata.CopySecurity(source, options, backend)
						if err != nil || !result.Completed || len(result.Failures) != 0 || result.Fallback {
							t.Fatal(result, err)
						}
						var wantEvents []string
						if options.ACL {
							wantEvents = append(wantEvents, "capture")
						}
						var queries []hostdata.SecurityCopyVolumeQuery
						strip := options.Stat && !options.AlwaysCopySetID && options.ForbidCopySetID
						if options.Stat && !options.AlwaysCopySetID && !options.ForbidCopySetID {
							for i, state := range []struct {
								value bool
								err   error
							}{sourceState, destinationState} {
								v := hostdata.SecurityCopySourceVolume
								if i == 1 {
									v = hostdata.SecurityCopyDestinationVolume
								}
								wantEvents = append(wantEvents, string(v))
								positive := state.value && state.err == nil
								queries = append(queries, hostdata.SecurityCopyVolumeQuery{Volume: v, NoSetID: positive, Err: state.err})
								if positive {
									strip = true
									break
								}
							}
						}
						wantMode := int32(0)
						if options.ACL {
							wantEvents = append(wantEvents, "security")
							wantMode = -1
						}
						if options.Stat {
							wantMode = 0106711
							if options.ACL {
								wantMode = 0106755
							} else {
								wantEvents = append(wantEvents, "mode")
							}
						}
						if strip {
							wantMode &^= 06000
						}
						if !reflect.DeepEqual(events, wantEvents) || !reflect.DeepEqual(result.VolumeQueries, queries) || gotMode != wantMode {
							t.Fatalf("events %v want %v; queries %+v want %+v; mode %o want %o", events, wantEvents, result.VolumeQueries, queries, gotMode, wantMode)
						}
						if flags != 0 && (result.Source.Properties.Mode == &mode || *result.Source.Properties.Mode != mode || result.Source.Mode != source.Mode) {
							t.Fatal("source cache changed or aliased")
						}
						wantWrites := 0
						if flags != 0 {
							wantWrites = 1
						}
						if result.Writes != wantWrites {
							t.Fatal("queries counted as writes", result)
						}
					})
				}
			}
		}
	}
}

func TestSecurityCopyVolumeEarlyFailures(t *testing.T) {
	policy := volumePolicyFunc(func(hostdata.SecurityCopyVolume) (bool, error) { t.Fatal("query after fatal error"); return false, nil })
	options := hostdata.SecurityCopyOptions{ACL: true, Stat: true, VolumePolicy: policy}
	for _, sourceFlag := range []bool{false, true} {
		mixed := options
		mixed.SourceNoSetID, mixed.DestinationNoSetID = sourceFlag, !sourceFlag
		r, e := hostdata.CopySecurity(hostdata.SecurityCopySource{}, mixed, copyBackend{})
		if !errors.Is(e, os.ErrInvalid) || r.Completed || r.Writes != 0 || len(r.VolumeQueries) != 0 {
			t.Fatal(r, e)
		}
	}
	failure := errors.New("source refused")
	sources := []hostdata.SecurityCopySource{
		{Properties: aclmeta.DarwinChmodProperties{RemoveACL: true}},
		{Properties: aclmeta.DarwinChmodProperties{RawSecurity: &appledouble.FileSecurity{}}},
		{},
		{Properties: aclmeta.DarwinChmodProperties{RawSecurity: &appledouble.FileSecurity{ACL: &appledouble.ACL{Entries: make([]appledouble.ACLEntry, 128)}}}},
	}
	for i, source := range sources {
		b := copyBackend{capture: func() (*appledouble.ACL, error) {
			if i == 2 {
				return nil, failure
			}
			return &appledouble.ACL{Entries: []appledouble.ACLEntry{{Flags: 17}}}, nil
		}}
		r, e := hostdata.CopySecurity(source, options, b)
		if e == nil || r.Completed || r.Writes != 0 || len(r.VolumeQueries) != 0 {
			t.Fatal(i, r, e)
		}
	}
	r, e := hostdata.CopySecurity(hostdata.SecurityCopySource{}, options, nil)
	if !errors.Is(e, os.ErrInvalid) || r.Completed {
		t.Fatal(r, e)
	}
	// A no-op never validates or touches even a contradictory policy.
	options.ACL, options.Stat, options.SourceNoSetID = false, false, true
	r, e = hostdata.CopySecurity(hostdata.SecurityCopySource{}, options, nil)
	if e != nil || !r.Completed || len(r.VolumeQueries) != 0 {
		t.Fatal(r, e)
	}
}
