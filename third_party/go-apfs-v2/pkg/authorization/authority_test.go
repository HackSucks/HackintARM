package authorization

import (
	"encoding/binary"
	"errors"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func wellKnown(code uint32) [16]byte {
	principal := [16]byte{0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef}
	binary.BigEndian.PutUint32(principal[12:], code)
	return principal
}

func TestCapturedPrincipalMembership(t *testing.T) {
	for _, tc := range []struct {
		name                                   string
		principal                              [16]byte
		member                                 Membership
		nilUser, failedUser, nonowner, noGroup bool
		applies                                bool
		err                                    error
	}{
		{name: "everyone", principal: wellKnown(12), applies: true},
		{name: "nobody", principal: wellKnown(0xfffffffe)},
		{name: "owner", principal: wellKnown(10), applies: true},
		{name: "nonowner", principal: wellKnown(10), nonowner: true},
		{name: "group", principal: wellKnown(16), applies: true},
		{name: "nonmember-group", principal: wellKnown(16), noGroup: true},
		{name: "unknown-user-group", principal: wellKnown(16), nilUser: true, err: ErrAuthority},
		{name: "failed-user-group", principal: wellKnown(16), nilUser: true, failedUser: true, applies: true},
		{name: "self", principal: [16]byte{1}, applies: true},
		{name: "member", principal: [16]byte{2}, member: Member, applies: true},
		{name: "not-member", principal: [16]byte{2}, member: NotMember},
		{name: "membership-failed", principal: [16]byte{2}, member: MembershipFailed, applies: true},
		{name: "membership-uncaptured", principal: [16]byte{2}, err: ErrAuthority},
		{name: "user-uncaptured", principal: [16]byte{2}, nilUser: true, err: ErrAuthority},
		{name: "user-failed", principal: [16]byte{2}, nilUser: true, failedUser: true, applies: true},
		{name: "unknown-well-known", principal: wellKnown(99), member: NotMember},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := fixtureAuthority()
			a.Membership = map[[16]byte]Membership{tc.principal: tc.member}
			if tc.nonowner {
				a.UID++
			}
			if tc.noGroup {
				a.Groups = nil
			}
			if tc.nilUser {
				a.UserUUID = nil
			}
			a.UserUUIDFailed = tc.failedUser
			stat := fixtureNode(false).Stat
			applies, err := Applies(a, tc.principal, true, stat)
			if applies != tc.applies || !errors.Is(err, tc.err) {
				t.Fatal(applies, err)
			}
			if tc.failedUser || tc.member == MembershipFailed {
				applies, err = Applies(a, tc.principal, false, stat)
				if applies || err != nil {
					t.Fatal("failed lookup granted allow", applies, err)
				}
			}
		})
	}
}

func TestOrderedACLResidualRights(t *testing.T) {
	ace := func(kind, rights uint32) appledouble.ACLEntry {
		return appledouble.ACLEntry{Principal: [16]byte{1}, Flags: kind, Rights: rights}
	}
	for _, tc := range []struct {
		name      string
		requested uint32
		entries   []appledouble.ACLEntry
		residual  uint32
		err       error
	}{
		{"no-request", 0, nil, 0, nil},
		{"complete-before-deny", 6, []appledouble.ACLEntry{ace(1, 6), ace(2, 6)}, 0, nil},
		{"partial-deny-already-allowed", 6, []appledouble.ACLEntry{ace(1, 2), ace(2, 2), ace(1, 4)}, 4, syscall.EACCES},
		{"split-grants", 6, []appledouble.ACLEntry{ace(1, 2), ace(1, 4)}, 0, nil},
		{"residual", 6, []appledouble.ACLEntry{ace(1, 2)}, 4, nil},
		{"inherit-only", 6, []appledouble.ACLEntry{ace(258, 6)}, 6, nil},
		{"audit", 6, []appledouble.ACLEntry{ace(3, 6)}, 6, nil},
		{"irrelevant", 6, []appledouble.ACLEntry{ace(2, Search)}, 6, nil},
		{"redundant-allow", 6, []appledouble.ACLEntry{ace(1, 2), ace(1, 2), ace(1, 4)}, 0, nil},
		{"generic-all", 6, []appledouble.ACLEntry{ace(1, 1<<21)}, 0, nil},
		{"generic-read-write", 6, []appledouble.ACLEntry{ace(1, 1<<24), ace(1, 1<<23)}, 0, nil},
		{"generic-execute", Search, []appledouble.ACLEntry{ace(1, 1<<22)}, 0, nil},
		{"nonmember", 6, []appledouble.ACLEntry{{Principal: wellKnown(0xfffffffe), Flags: 2, Rights: 6}}, 6, nil},
		{"unknown-principal", 6, []appledouble.ACLEntry{{Principal: [16]byte{9}, Flags: 2, Rights: 6}}, 6, ErrAuthority},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EvaluateACL(fixtureAuthority(), tc.entries, tc.requested, fixtureNode(false).Stat)
			if got != tc.residual || !errors.Is(err, tc.err) {
				t.Fatal(got, err)
			}
		})
	}
	const opaque = uint32(1 << 31)
	if got := ExpandRights(opaque); got != opaque {
		t.Fatalf("opaque rights changed: %x", got)
	}
}

func TestAuthoritySnapshotValidation(t *testing.T) {
	if _, err := CloneAuthority(nil); !errors.Is(err, ErrAuthority) {
		t.Fatal(err)
	}
	a := fixtureAuthority()
	a.UserUUIDFailed = true
	if _, err := CloneAuthority(&a); !errors.Is(err, ErrAuthority) {
		t.Fatal(err)
	}
	a = fixtureAuthority()
	a.Membership = map[[16]byte]Membership{{2}: 0}
	if _, err := CloneAuthority(&a); !errors.Is(err, ErrAuthority) {
		t.Fatal(err)
	}
	a.Membership[[16]byte{2}] = 4
	if _, err := CloneAuthority(&a); !errors.Is(err, ErrAuthority) {
		t.Fatal(err)
	}
	a.Membership[[16]byte{2}] = Member
	clone, err := CloneAuthority(&a)
	if err != nil {
		t.Fatal(err)
	}
	a.Membership[[16]byte{2}] = NotMember
	if clone.Membership[[16]byte{2}] != Member {
		t.Fatal("membership aliased caller")
	}
	// Endpoint compatibility permits an uncaptured process policy; New rejects it
	// for pathname evaluation. Cloning must preserve this distinction.
	a.Process = nil
	a.UserUUID = nil
	clone, err = CloneAuthority(&a)
	if err != nil || clone.Process != nil || clone.UserUUID != nil {
		t.Fatal(clone, err)
	}
}

func TestLongPathObservationSnapshot(t *testing.T) {
	a := fixtureAuthority()
	enabled := false
	a.Process.LongPaths = &enabled
	cloned, err := CloneAuthority(&a)
	if err != nil {
		t.Fatal(err)
	}
	enabled = true
	if cloned.Process.LongPaths == nil || *cloned.Process.LongPaths {
		t.Fatal("long-path policy aliased caller")
	}
}
