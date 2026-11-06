package acl

import (
	"context"
	"errors"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
)

// ErrACLIdentityLimit means the native account record exceeded the caller's
// buffer budget. It does not mean that the account is absent.
var ErrACLIdentityLimit = errors.New("native ACL identity record exceeds budget")

// NewNativeACLIdentityCapture records source Darwin directory-service queries
// with a 16MiB account-record budget. It is an explicit source acquisition API,
// never a fallback for identities belonging to a foreign image. Persist its
// Snapshot and use Snapshot.Resolvers on Linux/Windows; those hosts return
// errors.ErrUnsupported from this native constructor. The recorder is sequential.
func NewNativeACLIdentityCapture(ctx context.Context) (*appledouble.ACLIdentityCapture, error) {
	return NewNativeACLIdentityCaptureWithLimit(ctx, 16<<20)
}

// NewNativeACLIdentityCaptureWithLimit selects a per-query native record budget.
// Context is checked between native calls; an in-progress directory-service call
// cannot be interrupted. Failed or canceled queries are never recorded as absence.
func NewNativeACLIdentityCaptureWithLimit(ctx context.Context, maxRecordBytes int) (*appledouble.ACLIdentityCapture, error) {
	if ctx == nil || maxRecordBytes <= 0 {
		return nil, os.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return newNativeACLIdentityCapture(ctx, maxRecordBytes)
}
