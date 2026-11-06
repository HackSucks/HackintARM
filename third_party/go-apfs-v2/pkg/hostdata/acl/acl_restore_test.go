package acl

import (
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

type aclRestoreBackend struct {
	capture func() (ACLMetadata, error)
	write   func(ACLMetadata) error
	clear   func() error
}

func (b aclRestoreBackend) CaptureACL() (ACLMetadata, error) { return b.capture() }
func (b aclRestoreBackend) WriteACL(m ACLMetadata) error     { return b.write(m) }
func (b aclRestoreBackend) ClearSourceSecurity() error       { return b.clear() }

func TestRestoreACL(t *testing.T) {
	permission := errors.New("native permission denied")
	unsupported := errors.Join(errors.ErrUnsupported, errors.New("native ENOTSUP"))
	resetFailure := errors.New("source cache failure")
	captureFailure := errors.New("native capture failure")
	for _, tc := range []struct {
		name                 string
		captureErr, resetErr error
		writeErrors          []error
		want                 ACLRestoreResult
		events               []string
		cause                error
	}{
		{name: "write", writeErrors: []error{nil}, want: ACLRestoreResult{Applied: true, Attempts: 1}, events: []string{"capture", "write"}},
		{name: "permission", writeErrors: []error{permission}, want: ACLRestoreResult{Attempts: 1}, events: []string{"capture", "write"}, cause: permission},
		{name: "retry succeeds", writeErrors: []error{unsupported, nil}, want: ACLRestoreResult{Applied: true, Attempts: 2, Retried: true}, events: []string{"capture", "write", "clear", "write"}},
		{name: "retry unsupported", writeErrors: []error{unsupported, unsupported}, want: ACLRestoreResult{Attempts: 2, Retried: true}, events: []string{"capture", "write", "clear", "write"}, cause: unsupported},
		{name: "retry permission", writeErrors: []error{unsupported, permission}, want: ACLRestoreResult{Attempts: 2, Retried: true}, events: []string{"capture", "write", "clear", "write"}, cause: permission},
		{name: "clear fails", resetErr: resetFailure, writeErrors: []error{unsupported}, want: ACLRestoreResult{Attempts: 1}, events: []string{"capture", "write", "clear"}, cause: resetFailure},
		{name: "capture fails", captureErr: captureFailure, events: []string{"capture"}, cause: captureFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, empty := range []bool{false, true} {
				selected := &appledouble.ACL{Flags: 0x80000000, Entries: []appledouble.ACLEntry{{Principal: [16]byte{1}, Flags: 1, Rights: 2}}}
				if empty {
					selected = &appledouble.ACL{}
				}
				original := &appledouble.FileSecurity{OwnerUUID: [16]byte{2}, GroupUUID: [16]byte{3}, NoACLFlags: [4]byte{4}, Trailing: []byte{5}}
				expected, err := (appledouble.ACLUpdate{ACL: selected}).FileSecurity(original)
				if err != nil {
					t.Fatal(err)
				}
				expectedBytes, _ := expected.MarshalBinary()
				var events []string
				attempts := 0
				backend := aclRestoreBackend{
					capture: func() (ACLMetadata, error) {
						events = append(events, "capture")
						selected.Flags = 99
						return ACLMetadata{Security: original, UID: 0, GID: 0, Mode: 0}, tc.captureErr
					},
					write: func(m ACLMetadata) error {
						events = append(events, "write")
						b, e := m.Security.MarshalBinary()
						if e != nil || !reflect.DeepEqual(b, expectedBytes) || m.UID != 0 || m.GID != 0 || m.Mode != 0 {
							t.Fatal("request lost captured metadata", e)
						}
						// Deliberately corrupt the owned callback request. The retry must be equal.
						m.Security.OwnerUUID[0] = 99
						m.Security.ACL.Flags = 99
						if len(m.Security.ACL.Entries) > 0 {
							m.Security.ACL.Entries[0].Rights = 99
						}
						m.Security.Trailing = []byte{99}
						e = tc.writeErrors[attempts]
						attempts++
						return e
					},
					clear: func() error { events = append(events, "clear"); original.OwnerUUID[0] = 88; return tc.resetErr },
				}
				got, e := RestoreACL(appledouble.ACLUpdate{ACL: selected}, backend)
				if got != tc.want || !reflect.DeepEqual(events, tc.events) || !errors.Is(e, tc.cause) {
					t.Fatal(got, e, events)
				}
				if tc.resetErr != nil && !errors.Is(e, unsupported) {
					t.Fatal("lost preceding unsupported write", e)
				}
			}
		})
	}
}
func TestRestoreACLValidation(t *testing.T) {
	for _, update := range []appledouble.ACLUpdate{{}, {Invalid: true}} {
		r, e := RestoreACL(update, nil)
		if r != (ACLRestoreResult{}) || e != nil {
			t.Fatal("no-op backend", r, e)
		}
	}
	for _, update := range []appledouble.ACLUpdate{{ACL: &appledouble.ACL{}, Invalid: true}, {ACL: &appledouble.ACL{Entries: make([]appledouble.ACLEntry, 129)}}} {
		r, e := RestoreACL(update, nil)
		if r != (ACLRestoreResult{}) || !errors.Is(e, appledouble.ErrFileSecurity) {
			t.Fatal("invalid before callbacks", r, e)
		}
	}
	r, e := RestoreACL(appledouble.ACLUpdate{ACL: &appledouble.ACL{}}, nil)
	if r != (ACLRestoreResult{}) || !errors.Is(e, os.ErrInvalid) {
		t.Fatal(r, e)
	}
	r, e = RestoreACL(appledouble.ACLUpdate{ACL: &appledouble.ACL{}}, aclRestoreBackend{capture: func() (ACLMetadata, error) { return ACLMetadata{}, nil }})
	if r != (ACLRestoreResult{}) || !errors.Is(e, appledouble.ErrFileSecurity) {
		t.Fatal(r, e)
	}
}
