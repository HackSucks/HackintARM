package acl

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
	"unsafe"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

func TestACLIdentityCaptureDarwinLayout(t *testing.T) {
	if unsafe.Sizeof(darwinPasswd{}) != 72 || unsafe.Offsetof(darwinPasswd{}.UID) != 16 || unsafe.Offsetof(darwinPasswd{}.Expire) != 64 || unsafe.Sizeof(darwinGroup{}) != 32 || unsafe.Offsetof(darwinGroup{}.Members) != 24 {
		t.Fatal("native structure layout")
	}
	a, err := loadDarwinIdentity()
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range []bool{false, true} {
		id := uint32(os.Getuid())
		if group {
			id = uint32(os.Getgid())
		}
		p, found, err := a.account(context.Background(), appledouble.ACLIdentity{Group: group, ID: &id}, 1<<20)
		if err != nil || !found || p.ID != id || p.Group != group {
			t.Fatal(p, found, err)
		}
		c := identityCaptureWithABI(context.Background(), 1<<20, a)
		u, err := c.Resolve(appledouble.ACLIdentity{Group: group, ID: &id})
		if err != nil {
			t.Fatal(err)
		}
		named, err := c.Resolve(appledouble.ACLIdentity{Group: group, Name: p.Name})
		if err != nil || named != u {
			t.Fatal(named, err)
		}
		got, found, err := c.Lookup(u)
		if err != nil || !found || got != p {
			t.Fatal(got, found, err)
		}
		resolve, lookup, err := c.Snapshot().Resolvers()
		if err != nil {
			t.Fatal(err)
		}
		if replay, err := resolve(appledouble.ACLIdentity{Group: group, ID: &id}); err != nil || replay != u {
			t.Fatal(err)
		}
		if replay, yes, err := lookup(u); err != nil || !yes || replay != p {
			t.Fatal(err)
		}
	}
	if _, _, err = a.account(context.Background(), appledouble.ACLIdentity{Name: "root"}, 1); !errors.Is(err, ErrACLIdentityLimit) {
		t.Fatal(err)
	}
	for _, pair := range [][2]int{{1, 2}, {4096, 5000}, {int(^uint(0)>>1)/2 + 1, int(^uint(0) >> 1)}} {
		got := nextIdentitySize(pair[0], pair[1])
		if got < pair[0] || got > pair[1] {
			t.Fatal("overflow")
		}
	}
}
func TestACLIdentityCaptureDarwinLoaderErrors(t *testing.T) {
	want := errors.New("lookup")
	old := loadDarwinIdentity
	defer func() { loadDarwinIdentity = old }()
	loadDarwinIdentity = func() (*darwinIdentityABI, error) { return nil, want }
	if _, err := newNativeACLIdentityCapture(context.Background(), 64); !errors.Is(err, want) {
		t.Fatal(err)
	}
}
func identityTestABI() *darwinIdentityABI {
	a := &darwinIdentityABI{}
	fillUser := func(id uint32, r *darwinPasswd, b *byte, n uintptr, out **darwinPasswd) int32 {
		buf := unsafe.Slice(b, n)
		if len(buf) < 5 {
			return int32(syscall.ERANGE)
		}
		copy(buf, "user\x00")
		r.Name = b
		r.UID = id
		*out = r
		return 0
	}
	fillGroup := func(id uint32, r *darwinGroup, b *byte, n uintptr, out **darwinGroup) int32 {
		buf := unsafe.Slice(b, n)
		if len(buf) < 6 {
			return int32(syscall.ERANGE)
		}
		copy(buf, "group\x00")
		r.Name = b
		r.GID = id
		*out = r
		return 0
	}
	a.userID = fillUser
	a.userName = func(_ *byte, r *darwinPasswd, b *byte, n uintptr, out **darwinPasswd) int32 {
		return fillUser(5, r, b, n, out)
	}
	a.groupID = fillGroup
	a.groupName = func(_ *byte, r *darwinGroup, b *byte, n uintptr, out **darwinGroup) int32 {
		return fillGroup(6, r, b, n, out)
	}
	a.userUUID = func(id uint32, u *[16]byte) int32 { u[0] = byte(id); return 0 }
	a.groupUUID = a.userUUID
	a.uuidID = func(u *[16]byte, id *uint32, kind *int32) int32 { *id = uint32(u[0]); *kind = 0; return 0 }
	return a
}
func TestACLIdentityCaptureDarwinAccountErrors(t *testing.T) {
	id := uint32(5)
	for _, query := range []appledouble.ACLIdentity{{}, {Name: "user", ID: &id}, {Name: "bad\x00name"}} {
		if _, _, err := identityTestABI().account(context.Background(), query, 64); err == nil {
			t.Fatal("bad identity accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := identityTestABI().account(ctx, appledouble.ACLIdentity{ID: &id}, 64); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, group := range []bool{false, true} {
		for _, mode := range []string{"missing", "native-error", "wrong-pointer", "nil-name", "outside-name", "unterminated", "cancel", "retry"} {
			t.Run(mode+map[bool]string{false: "/user", true: "/group"}[group], func(t *testing.T) {
				a := identityTestABI()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				calls := 0
				user := a.userID
				groupfn := a.groupID
				a.userID = func(id uint32, r *darwinPasswd, b *byte, n uintptr, out **darwinPasswd) int32 {
					calls++
					switch mode {
					case "missing":
						return 0
					case "native-error":
						return int32(syscall.EIO)
					case "wrong-pointer":
						*out = &darwinPasswd{}
						return 0
					case "retry":
						if calls == 1 {
							return int32(syscall.ERANGE)
						}
					}
					code := user(id, r, b, n, out)
					switch mode {
					case "nil-name":
						r.Name = nil
					case "outside-name":
						r.Name = new(byte)
					case "unterminated":
						for i := range unsafe.Slice(b, n) {
							unsafe.Slice(b, n)[i] = 65
						}
					case "cancel":
						cancel()
					}
					return code
				}
				a.groupID = func(id uint32, r *darwinGroup, b *byte, n uintptr, out **darwinGroup) int32 {
					calls++
					switch mode {
					case "missing":
						return 0
					case "native-error":
						return int32(syscall.EIO)
					case "wrong-pointer":
						*out = &darwinGroup{}
						return 0
					case "retry":
						if calls == 1 {
							return int32(syscall.ERANGE)
						}
					}
					code := groupfn(id, r, b, n, out)
					switch mode {
					case "nil-name":
						r.Name = nil
					case "outside-name":
						r.Name = new(byte)
					case "unterminated":
						for i := range unsafe.Slice(b, n) {
							unsafe.Slice(b, n)[i] = 65
						}
					case "cancel":
						cancel()
					}
					return code
				}
				_, found, err := a.account(ctx, appledouble.ACLIdentity{Group: group, ID: &id}, 8192)
				if mode == "missing" {
					if found || err != nil {
						t.Fatal(found, err)
					}
				} else if mode == "retry" {
					if !found || err != nil || calls != 2 {
						t.Fatal(found, err, calls)
					}
				} else if err == nil {
					t.Fatal("native failure accepted")
				}
			})
		}
	}
}
func TestACLIdentityCaptureDarwinResolverErrors(t *testing.T) {
	id := uint32(5)
	query := appledouble.ACLIdentity{ID: &id}
	for _, mode := range []string{"missing", "account", "membership", "resolve-cancel", "lookup-cancel", "lookup-post-cancel", "unknown", "membership-error", "unknown-kind", "group"} {
		t.Run(mode, func(t *testing.T) {
			a := identityTestABI()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "missing":
				a.userID = func(uint32, *darwinPasswd, *byte, uintptr, **darwinPasswd) int32 { return 0 }
			case "account":
				a.userID = func(uint32, *darwinPasswd, *byte, uintptr, **darwinPasswd) int32 { return int32(syscall.EIO) }
			case "membership":
				a.userUUID = func(uint32, *[16]byte) int32 { return int32(syscall.EIO) }
			case "resolve-cancel":
				a.userUUID = func(uint32, *[16]byte) int32 { cancel(); return 0 }
			case "lookup-cancel":
				cancel()
			case "lookup-post-cancel":
				a.uuidID = func(*[16]byte, *uint32, *int32) int32 { cancel(); return 0 }
			case "unknown":
				a.uuidID = func(*[16]byte, *uint32, *int32) int32 { return int32(syscall.ENOENT) }
			case "membership-error":
				a.uuidID = func(*[16]byte, *uint32, *int32) int32 { return int32(syscall.EIO) }
			case "unknown-kind":
				a.uuidID = func(_ *[16]byte, _ *uint32, kind *int32) int32 { *kind = 9; return 0 }
			case "group":
				a.uuidID = func(_ *[16]byte, id *uint32, kind *int32) int32 { *id = 6; *kind = 1; return 0 }
			}
			c := identityCaptureWithABI(ctx, 8192, a)
			if mode == "missing" || mode == "account" || mode == "membership" || mode == "resolve-cancel" {
				u, err := c.Resolve(query)
				if mode == "missing" {
					if err != nil || u != [16]byte{} {
						t.Fatal(u, err)
					}
				} else if err == nil {
					t.Fatal("resolve failure accepted")
				}
				return
			}
			p, found, err := c.Lookup([16]byte{5})
			switch mode {
			case "unknown":
				if err != nil || found {
					t.Fatal(found, err)
				}
			case "group":
				if err != nil || !found || !p.Group {
					t.Fatal(p, found, err)
				}
			default:
				if err == nil {
					t.Fatal("lookup failure accepted")
				}
			}
		})
	}
}
