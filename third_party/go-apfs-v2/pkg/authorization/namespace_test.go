package authorization

import (
	"context"
	"errors"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

func fixtureAuthority() Authority {
	uuid := [16]byte{1}
	return Authority{UID: 501, Groups: []uint32{20}, UserUUID: &uuid, Process: &ProcessPolicy{}}
}
func fixtureNode(directory bool) Node {
	mode := uint32(0100600)
	if directory {
		mode = 0040700
	}
	return Node{Observed: true, Stat: hostdata.StatCopySource{UID: 501, GID: 20, Mode: mode}, Mount: &Mount{Identity: "observed-volume", Filesystem: "apfs"}, Identity: 10, SecurityState: SecurityAbsent}
}
func fixtureEvaluator(t *testing.T, a Authority) *Evaluator {
	t.Helper()
	e, err := New(osversion.Version{Major: 27}, &a)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func aceNode(n Node, a Authority, rights uint32, deny bool) Node {
	kind := uint32(1)
	if deny {
		kind = 2
	}
	n.SecurityState = SecurityPresent
	n.Security = &appledouble.FileSecurity{ACL: &appledouble.ACL{Entries: []appledouble.ACLEntry{{Principal: *a.UserUUID, Rights: rights, Flags: kind}}}}
	return n
}

func TestNamespaceObservationBoundary(t *testing.T) {
	a := fixtureAuthority()
	e := fixtureEvaluator(t, a)
	for _, tc := range []struct {
		name   string
		mutate func(*Node)
		want   error
	}{
		{"missing-stat", func(n *Node) { n.Observed = false }, ErrAuthority},
		{"missing-mount", func(n *Node) { n.Mount = nil }, ErrAuthority},
		{"missing-volume-identity", func(n *Node) { n.Mount.Identity = "" }, ErrAuthority},
		{"missing-filesystem", func(n *Node) { n.Mount.Filesystem = "" }, ErrAuthority},
		{"missing-security-observation", func(n *Node) { n.SecurityState = SecurityUncaptured }, ErrAuthority},
		{"invalid-security-observation", func(n *Node) { n.SecurityState = 4 }, ErrAuthority},
		{"missing-present-security", func(n *Node) { n.SecurityState = SecurityPresent }, ErrAuthority},
		{"false-absence", func(n *Node) { n.Security = &appledouble.FileSecurity{} }, ErrAuthority},
		{"opaque-trailing-security", func(n *Node) {
			n.SecurityState = SecurityPresent
			n.Security = &appledouble.FileSecurity{Trailing: []byte{1}}
		}, appledouble.ErrFileSecurity},
		{"invalid-acl", func(n *Node) {
			n.SecurityState = SecurityPresent
			n.Security = &appledouble.FileSecurity{ACL: &appledouble.ACL{Entries: make([]appledouble.ACLEntry, 129)}}
		}, appledouble.ErrFileSecurity},
		{"not-directory", func(n *Node) { n.Stat.Mode = 0100700 }, syscall.ENOTDIR},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := fixtureNode(true)
			tc.mutate(&n)
			if err := e.Search(t.Context(), n); !errors.Is(err, tc.want) {
				t.Fatalf("Search=%v want %v", err, tc.want)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := e.Search(ctx, fixtureNode(true)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, change := range []func(*Authority){func(a *Authority) { a.Groups = nil }, func(a *Authority) { a.Process = nil }, func(a *Authority) { a.UserUUIDFailed = true }} {
		a := fixtureAuthority()
		change(&a)
		if _, err := New(osversion.Version{Major: 27}, &a); !errors.Is(err, ErrAuthority) {
			t.Fatal(err)
		}
	}
	if _, err := New(osversion.Version{}, &a); !errors.Is(err, osversion.ErrMacOSProfile) {
		t.Fatal(err)
	}
}

func TestNamespaceIndependentPermissions(t *testing.T) {
	a := fixtureAuthority()
	e := fixtureEvaluator(t, a)
	parent := fixtureNode(true)
	leaf := fixtureNode(false)
	// A readonly volume permits search and rejects namespace writes.
	parent.Mount.Flags = 1
	if err := e.Search(t.Context(), parent); err != nil {
		t.Fatal(err)
	}
	if err := e.Create(t.Context(), parent, false); !errors.Is(err, syscall.EROFS) {
		t.Fatal(err)
	}
	parent = fixtureNode(true)
	parent.Stat.Flags = 4
	if err := e.Create(t.Context(), parent, false); err != nil {
		t.Fatal(err)
	}
	if err := e.Delete(t.Context(), parent, leaf); !errors.Is(err, syscall.EPERM) {
		t.Fatal(err)
	}
	parent = fixtureNode(true)
	parent.Stat.Flags = 2
	if err := e.Create(t.Context(), parent, false); !errors.Is(err, syscall.EPERM) {
		t.Fatal(err)
	}
	parent = fixtureNode(true)
	parent.Stat.Mode = 0040100
	if err := e.Search(t.Context(), parent); err != nil {
		t.Fatal(err)
	}
	if err := e.Create(t.Context(), parent, false); !errors.Is(err, syscall.EACCES) {
		t.Fatal(err)
	}
	parent = aceNode(parent, a, AddFile, false)
	if err := e.Create(t.Context(), parent, false); err != nil {
		t.Fatal(err)
	}
	if err := e.Create(t.Context(), parent, true); !errors.Is(err, syscall.EACCES) {
		t.Fatal(err)
	}
	parent = aceNode(fixtureNode(true), a, DeleteChild, true)
	leaf = aceNode(leaf, a, Delete, false)
	if err := e.Delete(t.Context(), parent, leaf); err != nil {
		t.Fatal(err)
	}
	leaf = aceNode(leaf, a, Delete, true)
	parent = aceNode(parent, a, DeleteChild, false)
	if err := e.Delete(t.Context(), parent, leaf); !errors.Is(err, syscall.EACCES) {
		t.Fatal(err)
	}
	parent = fixtureNode(true)
	parent.Stat.Mode = 0041777
	parent.Stat.UID = 0
	leaf = fixtureNode(false)
	leaf.Stat.UID = 0
	if err := e.Delete(t.Context(), parent, leaf); !errors.Is(err, syscall.EACCES) {
		t.Fatal(err)
	}
	parent = aceNode(parent, a, DeleteChild, false)
	if err := e.Delete(t.Context(), parent, leaf); err != nil {
		t.Fatal(err)
	}
	parent = fixtureNode(true)
	parent.Stat.Mode = 0041777
	if err := e.Delete(t.Context(), parent, leaf); err != nil {
		t.Fatal(err)
	}
	parent = fixtureNode(true)
	parent.Stat.Mode = 0040050
	parent.Stat.UID = 0
	if err := e.Search(t.Context(), parent); err != nil {
		t.Fatal(err)
	}
	parent.Stat.GID = 0
	if err := e.Search(t.Context(), parent); !errors.Is(err, syscall.EACCES) {
		t.Fatal(err)
	}
	parent.Stat.Mode = 0040001
	if err := e.Search(t.Context(), parent); err != nil {
		t.Fatal(err)
	}
}

func TestNamespaceRenameOrdering(t *testing.T) {
	a := fixtureAuthority()
	e := fixtureEvaluator(t, a)
	parent := fixtureNode(true)
	source := fixtureNode(false)
	target := fixtureNode(false)
	target.Identity = 20
	target = aceNode(target, a, Delete, true)
	source = aceNode(source, a, Delete, true)
	if err := e.Rename(t.Context(), parent, source, parent, &target); !errors.Is(err, syscall.EACCES) {
		t.Fatal(err)
	}
	other := fixtureNode(true)
	other.Mount.Identity = "other-volume"
	if err := e.Rename(t.Context(), parent, source, other, &target); !errors.Is(err, syscall.EXDEV) {
		t.Fatal(err)
	}
	target.Identity = source.Identity
	if err := e.Rename(t.Context(), parent, source, parent, &target); err != nil {
		t.Fatal(err)
	}
	target.Identity = 20
	source = fixtureNode(false)
	parent = aceNode(parent, a, AddFile, true)
	if err := e.Rename(t.Context(), parent, source, parent, &target); !errors.Is(err, syscall.EACCES) {
		t.Fatal(err)
	}
	parent = fixtureNode(true)
	if err := e.Rename(t.Context(), parent, source, parent, &target); !errors.Is(err, syscall.EACCES) {
		t.Fatal(err)
	}
	if err := e.Rename(t.Context(), parent, source, parent, nil); err != nil {
		t.Fatal(err)
	}
	source = fixtureNode(true)
	if err := e.Rename(t.Context(), parent, source, parent, nil); err != nil {
		t.Fatal(err)
	}
	invalid := fixtureNode(false)
	if err := e.Create(t.Context(), invalid, false); !errors.Is(err, syscall.ENOTDIR) {
		t.Fatal(err)
	}
	if err := e.Delete(t.Context(), invalid, source); !errors.Is(err, syscall.ENOTDIR) {
		t.Fatal(err)
	}
	invalid.Observed = false
	for _, err := range []error{e.Create(t.Context(), invalid, false), e.Delete(t.Context(), invalid, source), e.Delete(t.Context(), parent, invalid), e.Rename(t.Context(), invalid, source, parent, nil), e.Rename(t.Context(), parent, source, parent, &invalid)} {
		if !errors.Is(err, ErrAuthority) {
			t.Fatal(err)
		}
	}
	source = fixtureNode(false)
	source.Stat.Flags = 4
	if err := e.Delete(t.Context(), parent, source); !errors.Is(err, syscall.EPERM) {
		t.Fatal(err)
	}
}

func TestCapturedOwnerOverride(t *testing.T) {
	a := fixtureAuthority()
	a.Process.IgnoreNodePermissions = true
	e := fixtureEvaluator(t, a)
	parent := aceNode(fixtureNode(true), a, Search|DeleteChild, true)
	parent.Stat.Mode = 0040000
	parent.Stat.Flags = 2
	if err := e.Search(t.Context(), parent); err != nil {
		t.Fatal(err)
	}
	if err := e.Create(t.Context(), parent, false); err != nil {
		t.Fatal(err)
	}
	leaf := aceNode(fixtureNode(false), a, Delete, true)
	leaf.Stat.Flags = 2
	if err := e.Delete(t.Context(), parent, leaf); err != nil {
		t.Fatal(err)
	}
	leaf = fixtureNode(false)
	if err := e.Delete(t.Context(), parent, leaf); err != nil {
		t.Fatal(err)
	}
	parent.Stat.Flags = 0x20000
	if err := e.Create(t.Context(), parent, false); !errors.Is(err, syscall.EPERM) {
		t.Fatal(err)
	}
	parent = fixtureNode(true)
	parent.Stat.UID = 0
	parent.Stat.Mode = 0040000
	if err := e.Search(t.Context(), parent); !errors.Is(err, syscall.EACCES) {
		t.Fatal(err)
	}
	a.UID = 0
	e = fixtureEvaluator(t, a)
	if err := e.Search(t.Context(), parent); err != nil {
		t.Fatal(err)
	}
	if err := e.Create(t.Context(), parent, false); err != nil {
		t.Fatal(err)
	}
	if err := e.Delete(t.Context(), parent, leaf); err != nil {
		t.Fatal(err)
	}
	// The evaluator owns a snapshot rather than retaining mutable caller policy.
	a = fixtureAuthority()
	cloned, err := CloneAuthority(&a)
	if err != nil {
		t.Fatal(err)
	}
	a.Process.IgnoreNodePermissions = true
	a.Groups[0] = 0
	a.UserUUID[0] = 9
	if cloned.Process.IgnoreNodePermissions || cloned.Groups[0] != 20 || cloned.UserUUID[0] != 1 {
		t.Fatal("authority alias")
	}
}

func TestDirectoryRenameRequiresSourceAddSubdirectory(t *testing.T) {
	a := fixtureAuthority()
	e := fixtureEvaluator(t, a)
	sourceParent := fixtureNode(true)
	source := aceNode(fixtureNode(true), a, AddSubdirectory, true)
	source.Identity = 12
	targetParent := fixtureNode(true)
	targetParent.Identity = 13
	if err := e.Rename(t.Context(), sourceParent, source, targetParent, nil); !errors.Is(err, syscall.EACCES) {
		t.Fatal(err)
	}
	source.SecurityState = SecurityAbsent
	source.Security = nil
	if err := e.Rename(t.Context(), sourceParent, source, targetParent, nil); err != nil {
		t.Fatal(err)
	}
}
