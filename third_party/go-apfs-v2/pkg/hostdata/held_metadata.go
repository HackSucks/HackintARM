package hostdata

import (
	"os"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	aclmeta "github.com/deploymenttheory/go-apfs-v2/pkg/hostdata/acl"
)

// HeldMetadata binds native metadata operations to an already open file. The
// caller owns the file and must exclude unrelated metadata mutations. Each call
// pins its descriptor against concurrent Close; no method reopens a pathname.
// On non-Darwin hosts use LogicalMetadata for the complete Darwin metadata view.
type HeldMetadata struct {
	heldMetadataOperations
	// SourceCache is optional source state owned by this operation. An unsupported
	// deferred ACL write clears its security properties, never source storage.
	SourceCache *SecurityCopySource
}

type heldMetadataOperations interface {
	SecurityCopyBackend
	StatCopyBackend
	CaptureSecurity() (SecurityCopySource, error)
	CaptureSecurityState() (SecurityCopySource, StatCopySource, error)
	CaptureStat() (StatCopySource, error)
	CaptureACL() (aclmeta.ACLMetadata, error)
	WriteACL(aclmeta.ACLMetadata) error
	DisableCache() error
}

// NewHeldMetadata binds a Darwin descriptor. It neither takes ownership nor
// changes permissions. Unsupported native hosts return errors.ErrUnsupported;
// LogicalMetadata supplies the same operations without host authorization.
func NewHeldMetadata(file *os.File) (*HeldMetadata, error) {
	if file == nil {
		return nil, os.ErrInvalid
	}
	backend, err := newHeldMetadata(file)
	if err != nil {
		return nil, err
	}
	return &HeldMetadata{heldMetadataOperations: backend}, nil
}

// ClearSourceSecurity implements the deferred ACL cache reset only.
func (h *HeldMetadata) ClearSourceSecurity() error {
	clearMetadataSource(h.SourceCache)
	return nil
}

func clearMetadataSource(source *SecurityCopySource) {
	if source != nil {
		source.Properties.RawSecurity = nil
		source.Properties.OwnerUUID, source.Properties.GroupUUID = nil, nil
		source.Properties.RemoveACL = false
	}
}

// SourceCapture supplies descriptor source acquisition, retaining fallback stat
// fields on read failure as required by CaptureSecuritySource.
func (h *HeldMetadata) SourceCapture() SecuritySourceCapture {
	return SecuritySourceCapture{ReadSecurity: h.CaptureSecurity, ReadStat: func(prior SecuritySourceStat) (SecuritySourceStat, error) {
		stat, err := h.CaptureStat()
		if err != nil {
			return prior, err
		}
		return SecuritySourceStat{UID: stat.UID, GID: stat.GID, Mode: stat.Mode}, nil
	}}
}

func metadataACL(source SecurityCopySource) aclmeta.ACLMetadata {
	security := source.Properties.RawSecurity
	if security == nil {
		security = &appledouble.FileSecurity{}
	}
	if source.Properties.OwnerUUID != nil {
		security.OwnerUUID = *source.Properties.OwnerUUID
	}
	if source.Properties.GroupUUID != nil {
		security.GroupUUID = *source.Properties.GroupUUID
	}
	return aclmeta.ACLMetadata{Security: security, UID: source.UID, GID: source.GID, Mode: source.Mode}
}

func validateMetadataArguments(a aclmeta.DarwinChmodArguments) error {
	switch a.SecurityArgument {
	case aclmeta.DarwinSecurityNone, aclmeta.DarwinSecurityRemove:
		if a.Security != nil {
			return appledouble.ErrFileSecurity
		}
	case aclmeta.DarwinSecurityRecord:
		s, err := appledouble.ParseDarwinFileSecurity(a.Security)
		if err != nil || len(s.Trailing) != 0 {
			return appledouble.ErrFileSecurity
		}
	default:
		return appledouble.ErrFileSecurity
	}
	if a.Mode < -1 || a.Mode > 65535 {
		return os.ErrInvalid
	}
	return nil
}

// MetadataState owns logical Darwin stat and independently captured filesec
// properties. A logical state is preservation data, not host access control.
type MetadataState struct {
	Security SecurityCopySource
	Stat     StatCopySource
}

// LogicalMetadata implements the same security/stat protocols on Linux,
// Windows and macOS. It does not emulate host authorization or silently map
// Darwin principals to local users. Persist Snapshot into an image or carrier.
// Methods are not concurrent; the operation owns this state and SourceCache.
type LogicalMetadata struct {
	state         MetadataState
	SourceCache   *SecurityCopySource
	cacheDisabled bool
}

// DisableCache records the descriptor caching request on this logical endpoint.
// It does not change persistent inode metadata or the receiving host's cache.
func (m *LogicalMetadata) DisableCache() error { m.cacheDisabled = true; return nil }

// NewLogicalMetadata validates and copies the supplied complete state.
func NewLogicalMetadata(state MetadataState) (*LogicalMetadata, error) {
	source, err := cloneSecurityCopySource(state.Security)
	if err != nil {
		return nil, err
	}
	if source.UID != state.Stat.UID || source.GID != state.Stat.GID || source.Mode != state.Stat.Mode {
		return nil, os.ErrInvalid
	}
	state.Security = source
	return &LogicalMetadata{state: state}, nil
}

// Snapshot returns independent storage, suitable for durable carrier encoding.
func (m *LogicalMetadata) Snapshot() MetadataState {
	s, _ := cloneSecurityCopySource(m.state.Security)
	return MetadataState{Security: s, Stat: m.state.Stat}
}

func (m *LogicalMetadata) CaptureSecurity() (SecurityCopySource, error) {
	return cloneSecurityCopySource(m.state.Security)
}

// CaptureSecurityState returns security and stat from the same logical object.
func (m *LogicalMetadata) CaptureSecurityState() (SecurityCopySource, StatCopySource, error) {
	s, err := m.CaptureSecurity()
	return s, m.state.Stat, err
}
func (m *LogicalMetadata) CaptureStat() (StatCopySource, error) { return m.state.Stat, nil }
func (m *LogicalMetadata) CaptureACL() (aclmeta.ACLMetadata, error) {
	s, err := m.CaptureSecurity()
	return metadataACL(s), err
}
func (m *LogicalMetadata) CaptureDestinationACL() (*appledouble.ACL, error) {
	a, err := m.CaptureACL()
	return a.Security.ACL, err
}
func (m *LogicalMetadata) WriteACL(a aclmeta.ACLMetadata) error {
	r, err := a.DarwinChmodRequest()
	if err != nil {
		return err
	}
	return m.WriteSecurity(aclmeta.DarwinChmodArguments{UID: r.UID, GID: r.GID, Mode: int32(r.Mode), SecurityArgument: aclmeta.DarwinSecurityRecord, Security: r.Security})
}
func (m *LogicalMetadata) ClearSourceSecurity() error { clearMetadataSource(m.SourceCache); return nil }
func (m *LogicalMetadata) WriteSecurity(a aclmeta.DarwinChmodArguments) error {
	if err := validateMetadataArguments(a); err != nil {
		return err
	}
	s := &m.state.Security
	if a.UID != 0xffffff9b {
		s.UID, m.state.Stat.UID = a.UID, a.UID
		s.Properties.UID = &s.UID
	}
	if a.GID != 0xffffff9b {
		s.GID, m.state.Stat.GID = a.GID, a.GID
		s.Properties.GID = &s.GID
	}
	if a.Mode != -1 {
		_ = m.Chmod(uint16(a.Mode))
	}
	switch a.SecurityArgument {
	case aclmeta.DarwinSecurityRecord:
		raw, _ := appledouble.ParseDarwinFileSecurity(a.Security)
		s.Properties.RawSecurity = raw
		s.Properties.OwnerUUID, s.Properties.GroupUUID = &raw.OwnerUUID, &raw.GroupUUID
	case aclmeta.DarwinSecurityRemove:
		s.Properties.RawSecurity = nil
	}
	return nil
}
func (m *LogicalMetadata) SetACL(acl *appledouble.ACL) error {
	p := aclmeta.DarwinChmodProperties{RemoveACL: acl == nil}
	if acl != nil {
		p.RawSecurity = &appledouble.FileSecurity{ACL: acl}
	}
	a, err := p.ChmodArguments()
	if err != nil {
		return err
	}
	return m.WriteSecurity(a)
}
func (m *LogicalMetadata) Chown(uid, gid uint32) error {
	return m.WriteSecurity(aclmeta.DarwinChmodArguments{UID: uid, GID: gid, Mode: -1})
}
func (m *LogicalMetadata) Chmod(mode uint16) error {
	m.state.Stat.Mode = m.state.Stat.Mode&0170000 | uint32(mode)&07777
	m.state.Security.Mode = m.state.Stat.Mode
	m.state.Security.Properties.Mode = &m.state.Security.Mode
	return nil
}
func (m *LogicalMetadata) SetTimes(modify, access time.Time) error {
	m.state.Stat.Times.Modify, m.state.Stat.Times.Access = modify, access
	return nil
}
func (m *LogicalMetadata) ReadFlags() (uint32, error) { return m.state.Stat.Flags, nil }
func (m *LogicalMetadata) CompareAndSwapFlags(expected, replacement uint32) (uint32, error) {
	actual := m.state.Stat.Flags
	if expected == actual {
		m.state.Stat.Flags = replacement
	}
	return actual, nil
}
func (m *LogicalMetadata) Chflags(flags uint32) error { m.state.Stat.Flags = flags; return nil }

var (
	_ aclmeta.ACLRestoreBackend = (*HeldMetadata)(nil)
	_ aclmeta.ACLRestoreBackend = (*LogicalMetadata)(nil)
	_ heldMetadataOperations    = (*LogicalMetadata)(nil)
)
