package appledouble

import (
	"bytes"
	"errors"
	"fmt"
)

var (
	// ErrACLIdentitySnapshot identifies malformed or ambiguous captured identity data.
	ErrACLIdentitySnapshot = errors.New("appledouble: invalid ACL identity snapshot")
	// ErrACLIdentityUncaptured distinguishes an unrecorded query from a source
	// lookup that successfully established that an account does not exist.
	ErrACLIdentityUncaptured = errors.New("appledouble: ACL identity was not captured")
)

// ACLIdentityBinding records one successful source name/ID-to-UUID lookup.
// Exactly one of nonempty Name or non-nil ID must be supplied. Group selects
// the source account namespace. A zero UUID records confirmed source absence.
// Name is bytes so encoding/json preserves even non-UTF-8 source names.
type ACLIdentityBinding struct {
	Group bool
	Name  []byte
	ID    *uint32
	UUID  [16]byte
}

// ACLPrincipalBinding records one source UUID-to-account lookup for formatting.
// Found=false records confirmed absence and requires zero Group/Name/ID fields.
// This direction is captured separately: aliases and directory-service mappings
// mean that it cannot safely be inferred by reversing ACLIdentityBinding.
type ACLPrincipalBinding struct {
	UUID  [16]byte
	Found bool
	Group bool
	Name  []byte
	ID    uint32
}

// ACLIdentitySnapshot carries the successful identity queries needed by a
// captured ACL workload. Version must be 1. Standard encoding/json round trips
// are lossless, including arbitrary name bytes. This is application-owned
// metadata, not a new AppleDouble wire entry or a complete account database.
// Associate it with its source image/capture; never combine different sources.
// Apply input-size limits when decoding external snapshot data, then call
// Resolvers to validate it and obtain independent, immutable replay callbacks.
type ACLIdentitySnapshot struct {
	Version    uint32
	Identities []ACLIdentityBinding
	Principals []ACLPrincipalBinding
}

type aclIdentityKey struct {
	group   bool
	numeric bool
	name    string
	id      uint32
}

func identityKey(identity ACLIdentity) (aclIdentityKey, error) {
	if (identity.ID == nil) == (identity.Name == "") {
		return aclIdentityKey{}, fmt.Errorf("%w: supply exactly one name or ID", ErrACLIdentitySnapshot)
	}
	key := aclIdentityKey{group: identity.Group, name: identity.Name, numeric: identity.ID != nil}
	if identity.ID != nil {
		key.id = *identity.ID
	}
	return key, nil
}

func (key aclIdentityKey) identity() ACLIdentity {
	identity := ACLIdentity{Group: key.group, Name: key.name}
	if key.numeric {
		id := key.id
		identity.ID = &id
	}
	return identity
}

// Resolvers validates the snapshot and returns callbacks for ParseACLText,
// File.ACLUpdate and ACL.FormatText. Queries absent from the snapshot return
// ErrACLIdentityUncaptured; recorded negative results preserve native fallback.
// Duplicate query keys are rejected even when their values agree. Forward and
// reverse observations need not form a bijection and are not inferred from one
// another. The callbacks own their data and are safe for concurrent replay.
func (snapshot ACLIdentitySnapshot) Resolvers() (ACLResolver, ACLPrincipalResolver, error) {
	if snapshot.Version != 1 {
		return nil, nil, fmt.Errorf("%w: version %d", ErrACLIdentitySnapshot, snapshot.Version)
	}
	identities := make(map[aclIdentityKey][16]byte, len(snapshot.Identities))
	for _, binding := range snapshot.Identities {
		key, err := identityKey(ACLIdentity{Group: binding.Group, Name: string(binding.Name), ID: binding.ID})
		if err != nil {
			return nil, nil, err
		}
		if _, exists := identities[key]; exists {
			return nil, nil, fmt.Errorf("%w: duplicate identity", ErrACLIdentitySnapshot)
		}
		identities[key] = binding.UUID
	}
	principals := make(map[[16]byte]ACLPrincipalBinding, len(snapshot.Principals))
	for _, binding := range snapshot.Principals {
		if !binding.Found && (binding.Group || len(binding.Name) != 0 || binding.ID != 0) {
			return nil, nil, fmt.Errorf("%w: absent principal has account data", ErrACLIdentitySnapshot)
		}
		if _, exists := principals[binding.UUID]; exists {
			return nil, nil, fmt.Errorf("%w: duplicate principal", ErrACLIdentitySnapshot)
		}
		binding.Name = bytes.Clone(binding.Name)
		principals[binding.UUID] = binding
	}
	resolve := func(identity ACLIdentity) ([16]byte, error) {
		key, err := identityKey(identity)
		if err != nil {
			return [16]byte{}, err
		}
		uuid, found := identities[key]
		if !found {
			return [16]byte{}, ErrACLIdentityUncaptured
		}
		return uuid, nil
	}
	lookup := func(uuid [16]byte) (ACLPrincipal, bool, error) {
		binding, captured := principals[uuid]
		if !captured {
			return ACLPrincipal{}, false, ErrACLIdentityUncaptured
		}
		return ACLPrincipal{Group: binding.Group, Name: string(binding.Name), ID: binding.ID}, binding.Found, nil
	}
	return resolve, lookup, nil
}

// ACLIdentityCapture records successful queries through explicitly supplied
// source resolvers. Repeated queries reuse the first successful observation.
// Lookup errors are returned and never recorded as absence; retry is possible.
// Capture is sequential and is not safe for concurrent use. Use a new capture
// for each source/snapshot epoch and immutable Resolvers for concurrent replay.
// No host lookup, helper process or native library is used by this type.
type ACLIdentityCapture struct {
	resolve    ACLResolver
	lookup     ACLPrincipalResolver
	identities map[aclIdentityKey][16]byte
	principals map[[16]byte]ACLPrincipalBinding
	data       ACLIdentitySnapshot
}

// NewACLIdentityCapture creates a recorder. A nil source callback errors only
// if that lookup direction is used; explicit-UUID parsing needs no lookup.
func NewACLIdentityCapture(resolve ACLResolver, lookup ACLPrincipalResolver) *ACLIdentityCapture {
	return &ACLIdentityCapture{resolve: resolve, lookup: lookup,
		identities: make(map[aclIdentityKey][16]byte), principals: make(map[[16]byte]ACLPrincipalBinding)}
}

// Resolve is an ACLResolver that captures source name/ID-to-UUID observations.
func (capture *ACLIdentityCapture) Resolve(identity ACLIdentity) ([16]byte, error) {
	key, err := identityKey(identity)
	if err != nil {
		return [16]byte{}, err
	}
	if capture == nil || capture.resolve == nil {
		return [16]byte{}, ErrACLResolver
	}
	if uuid, found := capture.identities[key]; found {
		return uuid, nil
	}
	// The provider receives its own ID pointer, not the caller's or recorder's.
	uuid, err := capture.resolve(key.identity())
	if err != nil {
		return [16]byte{}, err
	}
	capture.identities[key] = uuid
	query := key.identity()
	capture.data.Identities = append(capture.data.Identities, ACLIdentityBinding{Group: query.Group, Name: []byte(query.Name), ID: query.ID, UUID: uuid})
	return uuid, nil
}

// Lookup is an ACLPrincipalResolver that captures source formatting identities.
func (capture *ACLIdentityCapture) Lookup(uuid [16]byte) (ACLPrincipal, bool, error) {
	if capture == nil || capture.lookup == nil {
		return ACLPrincipal{}, false, ErrACLResolver
	}
	if binding, found := capture.principals[uuid]; found {
		return ACLPrincipal{Group: binding.Group, Name: string(binding.Name), ID: binding.ID}, binding.Found, nil
	}
	principal, found, err := capture.lookup(uuid)
	if err != nil {
		return ACLPrincipal{}, false, err
	}
	if !found {
		principal = ACLPrincipal{}
	}
	binding := ACLPrincipalBinding{UUID: uuid, Found: found, Group: principal.Group, Name: []byte(principal.Name), ID: principal.ID}
	capture.principals[uuid] = binding
	capture.data.Principals = append(capture.data.Principals, binding)
	return principal, found, nil
}

// Snapshot returns independent data in first-observation order. It does not
// retain provider callbacks. A nil/unused capture produces an empty version-1
// snapshot whose replay rejects all queries as uncaptured.
func (capture *ACLIdentityCapture) Snapshot() ACLIdentitySnapshot {
	result := ACLIdentitySnapshot{Version: 1}
	if capture == nil {
		return result
	}
	for _, binding := range capture.data.Identities {
		binding.Name = bytes.Clone(binding.Name)
		if binding.ID != nil {
			id := *binding.ID
			binding.ID = &id
		}
		result.Identities = append(result.Identities, binding)
	}
	for _, binding := range capture.data.Principals {
		binding.Name = bytes.Clone(binding.Name)
		result.Principals = append(result.Principals, binding)
	}
	return result
}
