package hostdata_test

import (
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

func TestSecuritySourceCapture(t *testing.T) {
	original := errors.New("original read failure")
	failures := []error{nil, errors.Join(original, hostdata.ErrSecuritySourceNotPermitted), errors.Join(original, hostdata.ErrSecuritySourceNotSupported), original, fs.ErrPermission, fs.ErrNotExist}
	for _, kind := range []uint32{0, 0010000, 0020000, 0040000, 0060000, 0100000, 0120000, 0140000} {
		for ei, readErr := range failures {
			for behavior := 0; behavior < 3; behavior++ {
				t.Run(fmt.Sprintf("t%o-e%d-b%d", kind, ei, behavior), func(t *testing.T) {
					uid, gid, mode := uint32(42), uint32(43), uint32(0106755)
					raw := &appledouble.FileSecurity{ACL: &appledouble.ACL{Entries: []appledouble.ACLEntry{{Principal: [16]byte{1}, Flags: 1, Rights: 1}}}}
					initial := hostdata.SecurityCopySource{UID: 44, GID: 45, Mode: kind | 06711, Properties: aclmeta.DarwinChmodProperties{UID: &uid, GID: &gid, Mode: &mode, RawSecurity: raw}}
					calls := 0
					captured, e := hostdata.CaptureSecuritySource(hostdata.SecuritySourceCapture{
						ReadSecurity: func() (hostdata.SecurityCopySource, error) { calls++; return initial, readErr },
						ReadStat: func(previous hostdata.SecuritySourceStat) (hostdata.SecuritySourceStat, error) {
							calls++
							if previous != (hostdata.SecuritySourceStat{UID: 44, GID: 45, Mode: kind | 06711}) {
								t.Fatal(previous)
							}
							// The coordinator must already own a snapshot before the next callback.
							uid, gid, mode = 99, 99, 99
							raw.ACL.Entries[0].Rights = 99
							if behavior == 0 {
								return hostdata.SecuritySourceStat{UID: 46, GID: 47, Mode: 0100600}, nil
							}
							if behavior == 1 {
								return previous, original
							}
							return hostdata.SecuritySourceStat{}, original
						},
					})
					fallback := ei == 1 || ei == 2
					wanted := hostdata.SecuritySourceStat{UID: 44, GID: 45, Mode: kind | 06711}
					if fallback && behavior == 0 {
						wanted = hostdata.SecuritySourceStat{UID: 46, GID: 47, Mode: 0100600}
					}
					if fallback && behavior == 2 {
						wanted = hostdata.SecuritySourceStat{}
					}
					if captured.Source.UID != wanted.UID || captured.Source.GID != wanted.GID || captured.Source.Mode != wanted.Mode {
						t.Fatal(captured)
					}
					supported := wanted.Mode&0170000 == 0040000 || wanted.Mode&0170000 == 0100000 || wanted.Mode&0170000 == 0120000
					complete := (ei == 0 || fallback) && supported
					if captured.Completed != complete || (e == nil) != complete || captured.Fallback != fallback {
						t.Fatal(captured, e)
					}
					expectedCalls := 1
					if fallback {
						expectedCalls++
					}
					if calls != expectedCalls {
						t.Fatal("read order", calls)
					}
					if ei > 2 && !errors.Is(e, readErr) {
						t.Fatal("fatal cause lost", e)
					}
					if (ei == 0 || fallback) && !supported && !errors.Is(e, hostdata.ErrSecuritySourceType) {
						t.Fatal("type error lost", e)
					}
					expectedFailures := 0
					if readErr != nil {
						expectedFailures++
					}
					if fallback && behavior != 0 {
						expectedFailures++
					}
					if len(captured.Failures) != expectedFailures {
						t.Fatal(captured)
					}
					if readErr != nil && (captured.Failures[0].Operation != "security" || !errors.Is(captured.Failures[0].Err, readErr)) {
						t.Fatal("read cause")
					}
					if fallback && behavior != 0 && (captured.Failures[1].Operation != "stat" || !errors.Is(captured.Failures[1].Err, original)) {
						t.Fatal("stat cause")
					}
					if *captured.Source.Properties.UID != 42 || *captured.Source.Properties.GID != 43 || *captured.Source.Properties.Mode != 0106755 || captured.Source.Properties.RawSecurity.ACL.Entries[0].Rights != 1 {
						t.Fatal("properties changed or aliased")
					}
				})
			}
		}
	}
}

func TestSecuritySourceValidation(t *testing.T) {
	if r, e := hostdata.CaptureSecuritySource(hostdata.SecuritySourceCapture{}); !errors.Is(e, fs.ErrInvalid) || !reflect.DeepEqual(r, hostdata.SecuritySourceResult{}) {
		t.Fatal(r, e)
	}
	capture := hostdata.SecuritySourceCapture{ReadSecurity: func() (hostdata.SecurityCopySource, error) {
		return hostdata.SecurityCopySource{Mode: 0100644}, hostdata.ErrSecuritySourceNotSupported
	}}
	if r, e := hostdata.CaptureSecuritySource(capture); !errors.Is(e, fs.ErrInvalid) || !r.Fallback || r.Completed || len(r.Failures) != 1 {
		t.Fatal(r, e)
	}
	capture.ReadSecurity = func() (hostdata.SecurityCopySource, error) {
		return hostdata.SecurityCopySource{Properties: aclmeta.DarwinChmodProperties{RemoveACL: true}}, nil
	}
	if _, e := hostdata.CaptureSecuritySource(capture); !errors.Is(e, appledouble.ErrFileSecurity) {
		t.Fatal(e)
	}
	if r, e := hostdata.CopySecurityFrom(capture, hostdata.SecurityCopyOptions{}, nil); e != nil || !r.Copy.Completed || !reflect.DeepEqual(r.Capture, hostdata.SecuritySourceResult{}) {
		t.Fatal(r, e)
	}
	if r, e := hostdata.CopySecurityFrom(capture, hostdata.SecurityCopyOptions{ACL: true}, copyBackend{}); !errors.Is(e, appledouble.ErrFileSecurity) || r.Copy.Completed || r.Copy.Writes != 0 {
		t.Fatal(r, e)
	}
}

func TestSecuritySourceCopyOrder(t *testing.T) {
	var events []string
	source := hostdata.DecodeImageSecurity(42, 43, 0106755, nil).Source
	capture := hostdata.SecuritySourceCapture{ReadSecurity: func() (hostdata.SecurityCopySource, error) { events = append(events, "source"); return source, nil }}
	options := hostdata.SecurityCopyOptions{ACL: true, Stat: true, VolumePolicy: volumePolicyFunc(func(v hostdata.SecurityCopyVolume) (bool, error) {
		events = append(events, string(v))
		return false, nil
	})}
	backend := copyBackend{capture: func() (*appledouble.ACL, error) {
		events = append(events, "target")
		return &appledouble.ACL{Entries: []appledouble.ACLEntry{{Flags: 17, Rights: 1}}}, nil
	}, security: func(aclmeta.DarwinChmodArguments) error { events = append(events, "write"); return nil }}
	r, e := hostdata.CopySecurityFrom(capture, options, backend)
	if e != nil || !r.Capture.Completed || !r.Copy.Completed || !reflect.DeepEqual(events, []string{"source", "target", "source", "destination", "write"}) {
		t.Fatal(r, e, events)
	}
	if r.Capture.Source.Properties.RawSecurity != nil || r.Copy.Source.Properties.RawSecurity == nil {
		t.Fatal("acquisition cache overwritten by ACL selection")
	}
	// Failed acquisition cannot touch the target or policy provider.
	events = nil
	failure := errors.New("source unavailable")
	capture.ReadSecurity = func() (hostdata.SecurityCopySource, error) { events = append(events, "source"); return source, failure }
	r, e = hostdata.CopySecurityFrom(capture, options, backend)
	if !errors.Is(e, failure) || !reflect.DeepEqual(events, []string{"source"}) || r.Copy.Writes != 0 {
		t.Fatal(r, e, events)
	}
	events = nil
	capture.ReadSecurity = func() (hostdata.SecurityCopySource, error) { events = append(events, "source"); return source, nil }
	backend.capture = func() (*appledouble.ACL, error) { events = append(events, "target"); return nil, failure }
	r, e = hostdata.CopySecurityFrom(capture, options, backend)
	if !errors.Is(e, failure) || !r.Capture.Completed || len(r.Capture.Failures) != 0 || r.Copy.Completed || !reflect.DeepEqual(events, []string{"source", "target"}) {
		t.Fatal(r, e, events)
	}
}

type securityReaderFunc func(string) (hostdata.ImageSecurity, error)

func (f securityReaderFunc) Security(name string) (hostdata.ImageSecurity, error) { return f(name) }
func TestSecuritySourceImageCapture(t *testing.T) {
	for _, name := range []string{"", "../escape", "a/../b", "/absolute"} {
		capture := hostdata.ImageSecurityCapture(securityReaderFunc(func(string) (hostdata.ImageSecurity, error) {
			t.Fatal("invalid path read")
			return hostdata.ImageSecurity{}, nil
		}), name)
		if _, e := hostdata.CaptureSecuritySource(capture); !errors.Is(e, fs.ErrInvalid) {
			t.Fatal(e)
		}
	}
	if _, e := hostdata.CaptureSecuritySource(hostdata.ImageSecurityCapture(nil, ".")); !errors.Is(e, fs.ErrInvalid) {
		t.Fatal(e)
	}
	for _, name := range []string{".", "folder/file", "link"} {
		reader := securityReaderFunc(func(got string) (hostdata.ImageSecurity, error) {
			if got != name {
				t.Fatal(got)
			}
			return hostdata.DecodeImageSecurity(0, 0, 0120000, nil), nil
		})
		r, e := hostdata.CaptureSecuritySource(hostdata.ImageSecurityCapture(reader, name))
		if e != nil || !r.Completed || r.Source.Mode != 0120000 || r.Source.UID != 0 || r.Source.Properties.UID == nil {
			t.Fatal(r, e)
		}
	}
	failure := errors.New("image I/O failure")
	reader := securityReaderFunc(func(string) (hostdata.ImageSecurity, error) { return hostdata.ImageSecurity{}, failure })
	if _, e := hostdata.CaptureSecuritySource(hostdata.ImageSecurityCapture(reader, "file")); !errors.Is(e, failure) {
		t.Fatal(e)
	}
}
