package recompression

import (
	"encoding/binary"
	"errors"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

func recompressionAccessFixture(t *testing.T, entries ...appledouble.ACLEntry) (*recompressionAccess, hostdata.StatCopySource) {
	t.Helper()
	uid, gid := uint32(501), uint32(20)
	identity := [16]byte{1}
	a, err := newRecompressionAccess(metatransport.Record{Darwin: metatransport.DarwinState{UID: &uid, GID: &gid}}, &appledouble.FileSecurity{ACL: &appledouble.ACL{Entries: entries}}, &Authority{UID: uid, Groups: []uint32{gid}, UserUUID: &identity}, 0)
	if err != nil {
		t.Fatal(err)
	}
	a.profile = osversion.MacOS27
	return a, hostdata.StatCopySource{UID: uid, GID: gid, Mode: 0100600}
}
func recompressionWellKnown(code uint32) [16]byte {
	id := [16]byte{0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef}
	binary.BigEndian.PutUint32(id[12:], code)
	return id
}
func TestRecompressionAccessAdmissionAndStages(t *testing.T) {
	for _, tc := range []struct {
		name, operation           string
		mode, flags, volume, deny uint32
		want                      error
	}{
		{name: "ordinary", operation: "open-data", mode: 0100600},
		{name: "no-mode", operation: "open-data", mode: 0100000, want: syscall.EACCES},
		{name: "write-only", operation: "open-data", mode: 0100200, want: syscall.EACCES},
		{name: "read-only", operation: "open-data", mode: 0100400, want: syscall.EACCES},
		{name: "readonly-volume", operation: "open-data", mode: 0100600, volume: 1, want: syscall.EROFS},
		{name: "immutable", operation: "open-data", mode: 0100600, flags: 2, want: syscall.EPERM},
		{name: "append", operation: "open-data", mode: 0100600, flags: 4, want: syscall.EPERM},
		{name: "system-immutable", operation: "open-data", mode: 0100600, flags: 0x20000, want: syscall.EPERM},
		{name: "deny-read", operation: "open-data", mode: 0100600, deny: recompressionReadData, want: syscall.EACCES},
		{name: "deny-write", operation: "open-data", mode: 0100600, deny: recompressionWriteData, want: syscall.EACCES},
		{name: "deny-read-fork", operation: "open-fork", mode: 0100600, deny: recompressionReadXattr, want: syscall.EACCES},
		{name: "deny-write-fork", operation: "open-fork", mode: 0100600, deny: recompressionWriteXattr, want: syscall.EACCES},
		{name: "deny-writeattr", operation: "times", mode: 0100600, deny: recompressionWriteAttributes, want: syscall.EPERM},
		{name: "deny-writeattr-activation", operation: "flags", mode: 0100600, deny: recompressionWriteAttributes},
		{name: "no-user-xattrs", operation: "attribute", mode: 0100600, volume: 0x01000000, want: syscall.EACCES},
		{name: "attribute", operation: "attribute", mode: 0100600},
		{name: "truncate", operation: "truncate", mode: 0100600},
		{name: "mode-owner", operation: "chmod", mode: 0100000, deny: recompressionWriteSecurity},
		{name: "flags-owner", operation: "flags", mode: 0100000, flags: 2},
		{name: "unknown", operation: "unknown", mode: 0100600, want: metatransport.ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, stat := recompressionAccessFixture(t, appledouble.ACLEntry{Principal: [16]byte{1}, Flags: 2, Rights: tc.deny})
			stat.Mode, stat.Flags, a.volume = tc.mode, tc.flags, tc.volume
			if err := a.authorize(tc.operation, stat); !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
}
func TestRecompressionAccessOrderedACL(t *testing.T) {
	allow := func(rights uint32) appledouble.ACLEntry {
		return appledouble.ACLEntry{Principal: [16]byte{1}, Flags: 1, Rights: rights}
	}
	deny := func(rights uint32) appledouble.ACLEntry {
		return appledouble.ACLEntry{Principal: [16]byte{1}, Flags: 2, Rights: rights}
	}
	for _, tc := range []struct {
		name    string
		entries []appledouble.ACLEntry
		mode    uint32
		want    error
	}{
		{"allow-all-before-deny", []appledouble.ACLEntry{allow(6), deny(6)}, 0100000, nil},
		{"partial-allow-then-deny-already-allowed", []appledouble.ACLEntry{allow(2), deny(2), allow(4)}, 0100600, syscall.EACCES},
		{"split-allow", []appledouble.ACLEntry{allow(2), allow(4)}, 0100000, nil},
		{"residual-posix", []appledouble.ACLEntry{allow(2)}, 0100200, nil},
		{"residual-posix-denied", []appledouble.ACLEntry{allow(2)}, 0100400, syscall.EACCES},
		{"ignore-inherit-only", []appledouble.ACLEntry{{Principal: [16]byte{1}, Flags: 2 | 256, Rights: 6}}, 0100600, nil},
		{"ignore-audit", []appledouble.ACLEntry{{Principal: [16]byte{1}, Flags: 3, Rights: 6}}, 0100600, nil},
		{"unrelated-rights-need-no-identity", []appledouble.ACLEntry{{Principal: [16]byte{9}, Flags: 2, Rights: 1 << 3}}, 0100600, nil},
		{"redundant-allow", []appledouble.ACLEntry{allow(2), allow(2), allow(4)}, 0100000, nil},
		{"generic-all", []appledouble.ACLEntry{allow(1 << 21)}, 0100000, nil},
		{"generic-read-write", []appledouble.ACLEntry{allow(1 << 24), allow(1 << 23)}, 0100000, nil},
		{"generic-execute-unrelated", []appledouble.ACLEntry{deny(1 << 22)}, 0100600, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, stat := recompressionAccessFixture(t, tc.entries...)
			stat.Mode = tc.mode
			if e := a.authorize("open-data", stat); !errors.Is(e, tc.want) {
				t.Fatal(e, tc.want)
			}
		})
	}
}
func TestRecompressionAccessPrincipals(t *testing.T) {
	for _, tc := range []struct {
		name                                   string
		principal                              [16]byte
		member                                 Membership
		userNil, userFailed, nonowner, noGroup bool
		want                                   error
	}{
		{name: "everybody", principal: recompressionWellKnown(12), want: syscall.EACCES},
		{name: "nobody", principal: recompressionWellKnown(0xfffffffe)},
		{name: "owner", principal: recompressionWellKnown(10), want: syscall.EACCES},
		{name: "other-owner", principal: recompressionWellKnown(10), nonowner: true},
		{name: "group", principal: recompressionWellKnown(16), want: syscall.EACCES},
		{name: "other-group", principal: recompressionWellKnown(16), noGroup: true},
		{name: "uncaptured-user-group", principal: recompressionWellKnown(16), userNil: true, want: ErrAuthority},
		{name: "failed-user-group", principal: recompressionWellKnown(16), userNil: true, userFailed: true, want: syscall.EACCES},
		{name: "self", principal: [16]byte{1}, want: syscall.EACCES},
		{name: "member", principal: [16]byte{2}, member: Member, want: syscall.EACCES},
		{name: "notmember", principal: [16]byte{2}, member: NotMember},
		{name: "lookup-failure", principal: [16]byte{2}, member: MembershipFailed, want: syscall.EACCES},
		{name: "uncaptured", principal: [16]byte{2}, want: ErrAuthority},
		{name: "uncaptured-user", principal: [16]byte{2}, userNil: true, want: ErrAuthority},
		{name: "failed-user", principal: [16]byte{2}, userNil: true, userFailed: true, want: syscall.EACCES},
		{name: "unknown-wellknown-code", principal: recompressionWellKnown(99), member: NotMember},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, stat := recompressionAccessFixture(t, appledouble.ACLEntry{Principal: tc.principal, Flags: 2, Rights: 6})
			stat.Mode = 0100666
			a.authority.Membership = map[[16]byte]Membership{tc.principal: tc.member}
			if tc.nonowner {
				a.authority.UID++
			}
			if tc.noGroup {
				a.authority.Groups = nil
			}
			if tc.userNil {
				a.authority.UserUUID = nil
			}
			a.authority.UserUUIDFailed = tc.userFailed
			if e := a.authorize("open-data", stat); !errors.Is(e, tc.want) {
				t.Fatal(e, tc.want)
			}
		})
	}
	for _, userFailed := range []bool{false, true} {
		a, stat := recompressionAccessFixture(t, appledouble.ACLEntry{Principal: [16]byte{2}, Flags: 1, Rights: 6})
		stat.Mode = 0100000
		a.authority.Membership = map[[16]byte]Membership{{2}: MembershipFailed}
		if userFailed {
			a.authority.UserUUID = nil
			a.authority.UserUUIDFailed = true
		}
		if e := a.authorize("open-data", stat); !errors.Is(e, syscall.EACCES) {
			t.Fatal(e)
		}
	}
}
func TestRecompressionAccessOwnership(t *testing.T) {
	a, stat := recompressionAccessFixture(t)
	stat.Mode = 0100060
	a.authority.UID++
	if e := a.authorize("open-data", stat); e != nil {
		t.Fatal(e)
	}
	a.authority.Groups = nil
	if e := a.authorize("open-data", stat); !errors.Is(e, syscall.EACCES) {
		t.Fatal(e)
	}
	stat.Mode = 0100006
	if e := a.authorize("open-data", stat); e != nil {
		t.Fatal(e)
	}
	for _, op := range []string{"times", "chmod", "flags"} {
		if e := a.authorize(op, stat); !errors.Is(e, syscall.EPERM) {
			t.Fatal(op, e)
		}
	}
	a.authority.UID = 0
	stat.Mode = 0100000
	if e := a.authorize("open-data", stat); e != nil {
		t.Fatal(e)
	}
	stat.Flags = 2
	if e := a.authorize("open-data", stat); !errors.Is(e, syscall.EPERM) {
		t.Fatal(e)
	}
	a, stat = recompressionAccessFixture(t)
	if e := a.authorize("times", stat); e != nil {
		t.Fatal(e)
	}
	if e := a.chmod(stat, 0600); e != nil {
		t.Fatal(e)
	}
	if e := a.chmod(stat, 04600); e != nil {
		t.Fatal(e)
	}
	if e := a.chmod(stat, 02600); e != nil {
		t.Fatal(e)
	}
	a.authority.Groups = nil
	if e := a.chmod(stat, 02600); !errors.Is(e, syscall.EPERM) {
		t.Fatal(e)
	}
	a.authority.UID++
	if e := a.chmod(stat, 04600); !errors.Is(e, syscall.EPERM) {
		t.Fatal(e)
	}
	a.authority.UID = 0
	if e := a.chmod(stat, 02600); e != nil {
		t.Fatal(e)
	}
}
func TestRecompressionAccessCaptureValidation(t *testing.T) {
	uid, gid := uint32(501), uint32(20)
	record := metatransport.Record{Darwin: metatransport.DarwinState{UID: &uid, GID: &gid}}
	identity := [16]byte{1}
	authority := &Authority{UID: uid, Groups: []uint32{gid}, UserUUID: &identity, Membership: map[[16]byte]Membership{{2}: Member}}
	for _, r := range []metatransport.Record{{}, {Darwin: metatransport.DarwinState{UID: &uid}}, {Darwin: metatransport.DarwinState{GID: &gid}}} {
		if _, e := newRecompressionAccess(r, nil, authority, 0); !errors.Is(e, ErrAuthority) {
			t.Fatal(e)
		}
	}
	if _, e := newRecompressionAccess(record, nil, nil, 0); !errors.Is(e, ErrAuthority) {
		t.Fatal(e)
	}
	authority.UserUUIDFailed = true
	if _, e := newRecompressionAccess(record, nil, authority, 0); !errors.Is(e, ErrAuthority) {
		t.Fatal(e)
	}
	authority.UserUUIDFailed = false
	authority.Membership[[16]byte{2}] = 99
	if _, e := newRecompressionAccess(record, nil, authority, 0); !errors.Is(e, ErrAuthority) {
		t.Fatal(e)
	}
	authority.Membership[[16]byte{2}] = Member
	for _, security := range []*appledouble.FileSecurity{{Trailing: []byte{1}}, {ACL: &appledouble.ACL{}, NoACLFlags: [4]byte{1}}} {
		if _, e := newRecompressionAccess(record, security, authority, 0); !errors.Is(e, appledouble.ErrFileSecurity) {
			t.Fatal(e)
		}
	}
	a, e := newRecompressionAccess(record, nil, authority, 0)
	if e != nil {
		t.Fatal(e)
	}
	authority.Groups[0] = 99
	authority.Membership[[16]byte{2}] = NotMember
	identity[0] = 9
	if a.authority.Groups[0] != 20 || a.authority.Membership[[16]byte{2}] != Member || *a.authority.UserUUID != ([16]byte{1}) {
		t.Fatal("authority aliased caller")
	}
	if _, e := newRecompressionAccess(record, &appledouble.FileSecurity{}, &Authority{}, 0); e != nil {
		t.Fatal(e)
	}
}

func TestRecompressionAccessVersionRoutes(t *testing.T) {
	a, stat := recompressionAccessFixture(t, appledouble.ACLEntry{Principal: [16]byte{1}, Flags: 2, Rights: recompressionReadXattr})
	a.profile = osversion.MacOS15
	if e := a.authorize("open-fork", stat); e != nil {
		t.Fatal(e)
	}
	a.profile = osversion.MacOS26
	if e := a.authorize("open-fork", stat); !errors.Is(e, syscall.EACCES) {
		t.Fatal(e)
	}
	a.profile = 0
	if e := a.authorize("open-fork", stat); !errors.Is(e, osversion.ErrMacOSProfile) {
		t.Fatal(e)
	}
	a, stat = recompressionAccessFixture(t)
	a.volume = 1
	if e := a.authorize("truncate", stat); !errors.Is(e, syscall.EROFS) {
		t.Fatal(e)
	}
	a.volume = 0
	stat.Flags = 4
	if e := a.authorize("truncate", stat); !errors.Is(e, syscall.EPERM) {
		t.Fatal(e)
	}
	stat.Flags = 2
	if e := a.authorize("truncate", stat); e != nil {
		t.Fatal(e)
	}
}
