package recompression

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io/fs"
	"path"
	"strings"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v2/pkg/authorization"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
	"github.com/deploymenttheory/go-apfs-v2/pkg/osversion"
)

// PathObservation records explicit source security and mount context for one
// original manifest name. SecurityAbsent is a real observed absence, not a nil
// source value guessed from incomplete xattr extraction. Mount is the volume
// where this logical operation occurs, not the receiving host's storage volume.
type PathObservation struct {
	Security authorization.SecurityState
	Mount    authorization.Mount
	Identity uint64
}

// PathCapture declares the source namespace represented by a carrier. Root is
// an original manifest directory name. FilesystemRoot explicitly permits absolute
// symlink targets to start there. Complete declares observed namespace absence:
// when false, an unrecorded name is uncaptured context instead of ENOENT.
type PathCapture struct {
	Root           string
	FilesystemRoot bool
	Complete       bool
	Nodes          map[string]PathObservation
}

// PathContext binds explicit observations to one store, manifest and generation.
// It is immutable; a changed manifest requires a new binding. A context cannot be
// reused for another carrier which happens to have the same generation number.
type PathContext struct {
	store      *metatransport.Store
	generation uint64
	digest     [32]byte
	capture    PathCapture
}

// NewPathContext binds supplied observations; it does not capture permissions
// from the receiver or infer missing source fields. Required observations are
// validated in actual pathname traversal order by RecompressPath.
func NewPathContext(ctx context.Context, store *metatransport.Store, generation uint64, capture PathCapture) (*PathContext, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if store == nil || !fs.ValidPath(capture.Root) {
		return nil, metatransport.ErrInvalid
	}
	manifest, err := store.Load(ctx)
	if err != nil {
		return nil, err
	}
	if manifest.Generation != generation {
		return nil, metatransport.ErrConflict
	}
	found := false
	for _, record := range manifest.Records {
		if record.Original == capture.Root {
			found = record.Kind == "directory"
			break
		}
	}
	if !found {
		return nil, ErrAuthority
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	copy := capture
	copy.Nodes = make(map[string]PathObservation, len(capture.Nodes))
	for name, value := range capture.Nodes {
		if value.Mount.CaseSensitive != nil {
			policy := *value.Mount.CaseSensitive
			value.Mount.CaseSensitive = &policy
		}
		copy.Nodes[name] = value
	}
	return &PathContext{store: store, generation: generation, digest: sha256.Sum256(encoded), capture: copy}, nil
}

// PathOptions selects the same endpoint lifecycle as Options after independent
// source pathname authorization. Context must be bound to the expected store and
// generation. Volume must match the selected leaf's captured logical mount.
type PathOptions struct {
	Options
	Context *PathContext
}

// RecompressPath follows an original POSIX path relative to Context's Root,
// including symlinks and dot components, authorizing every directory actually
// traversed. Absolute symlink targets require an explicit filesystem-root capture.
// It requires observed security presence/absence for ancestors AND the leaf.
// Missing observations never fall back to RecompressRecord. The caller excludes
// external payload/metadata mutation, as for the underlying carrier operation.
func RecompressPath(ctx context.Context, store *metatransport.Store, name string, expected uint64, options PathOptions) (Result, error) {
	return recompressPath(ctx, store, name, expected, options, hostdata.Recompress)
}

type pathCarrier struct {
	carrier
	manifest metatransport.Manifest
}

func (s pathCarrier) Load(ctx context.Context) (metatransport.Manifest, error) {
	return s.manifest, ctx.Err()
}

func recompressPath(ctx context.Context, store *metatransport.Store, name string, expected uint64, options PathOptions, operation recompressionOperation) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	bound := options.Context
	if bound == nil || store == nil || bound.store != store {
		return Result{}, ErrAuthority
	}
	if bound.generation != expected {
		return Result{}, metatransport.ErrConflict
	}
	manifest, err := store.Load(ctx)
	if err != nil {
		return Result{}, err
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return Result{}, err
	}
	if manifest.Generation != expected || sha256.Sum256(encoded) != bound.digest {
		return Result{}, metatransport.ErrConflict
	}
	// Snapshot once: pathname limits, directory checks and endpoint acquisition
	// consume the same captured process/credential context.
	captured, err := authorization.CloneAuthority(options.Authority)
	if err != nil {
		return Result{}, err
	}
	if captured.Process == nil || captured.Process.LongPaths == nil {
		return Result{}, ErrAuthority
	}
	options.Authority = &captured
	limit := 1024
	if *captured.Process.LongPaths {
		limit = 8192
	}
	evaluator, err := authorization.New(options.Target, options.Authority)
	if err != nil {
		return Result{}, err
	}
	records := make(map[string]metatransport.Record, len(manifest.Records))
	for _, record := range manifest.Records {
		records[record.Original] = record
	}
	resolved, leaf, err := resolvePath(ctx, store, records, bound.capture, evaluator, name, limit, osversion.MacOSProfile(options.Target.Major))
	if err != nil {
		return Result{}, err
	}
	if options.Volume == nil || options.Volume.Filesystem != leaf.Mount.Filesystem || options.Volume.Flags != leaf.Mount.Flags {
		return Result{}, ErrAuthority
	}
	return recompressRecord(ctx, pathCarrier{store, manifest}, resolved, expected, options.Options, operation)
}

func observedNode(ctx context.Context, store carrier, record metatransport.Record, observation PathObservation) (authorization.Node, error) {
	stat := record.Darwin
	if stat.UID == nil || stat.GID == nil || stat.Mode == nil || stat.Flags == nil {
		return authorization.Node{}, ErrAuthority
	}
	values, err := store.BorrowRecordAttributes(ctx, record)
	if err != nil {
		return authorization.Node{}, err
	}
	node := authorization.Node{Observed: true, Stat: hostdata.StatCopySource{UID: *stat.UID, GID: *stat.GID, Mode: *stat.Mode, Flags: *stat.Flags}, Mount: &observation.Mount, Identity: observation.Identity, SecurityState: observation.Security}
	value := values["com.apple.system.Security"]
	if observation.Security == authorization.SecurityAbsent && value != nil || observation.Security == authorization.SecurityPresent && value == nil || observation.Security != authorization.SecurityAbsent && observation.Security != authorization.SecurityPresent {
		return authorization.Node{}, ErrAuthority
	}
	if value != nil {
		node.Security, err = readRecompressionSecurity(value)
		if err != nil {
			return authorization.Node{}, err
		}
	}
	if node.Mount.Identity == "" || node.Mount.Filesystem == "" {
		return authorization.Node{}, ErrAuthority
	}
	return node, nil
}

func resolvePath(ctx context.Context, store carrier, records map[string]metatransport.Record, capture PathCapture, evaluator *authorization.Evaluator, name string, limit int, profile osversion.MacOSProfile) (string, authorization.Node, error) {
	if strings.IndexByte(name, 0) >= 0 {
		return "", authorization.Node{}, metatransport.ErrInvalid
	}
	// namei copies the original C pathname before search; MAXPATHLEN includes
	// its terminating NUL. Empty pathname lookup reports ENOENT before search.
	if len(name) >= limit {
		return "", authorization.Node{}, syscall.ENAMETOOLONG
	}
	if name == "" {
		return "", authorization.Node{}, syscall.ENOENT
	}
	if strings.HasPrefix(name, "/") && !capture.FilesystemRoot {
		return "", authorization.Node{}, ErrAuthority
	}
	parts := strings.Split(name, "/")
	current := capture.Root
	links := 0
	missing := func() error {
		if capture.Complete {
			return syscall.ENOENT
		}
		return ErrAuthority
	}
	node := func(name string) (authorization.Node, error) {
		r, ok := records[name]
		if !ok {
			return authorization.Node{}, missing()
		}
		observation, ok := capture.Nodes[name]
		if !ok {
			return authorization.Node{}, ErrAuthority
		}
		return observedNode(ctx, store, r, observation)
	}
	for len(parts) > 0 {
		if err := ctx.Err(); err != nil {
			return "", authorization.Node{}, err
		}
		component := parts[0]
		parts = parts[1:]
		if component == "" {
			if len(parts) == 0 && records[current].Kind != "directory" {
				return "", authorization.Node{}, syscall.ENOTDIR
			}
			continue
		}
		directory, err := node(current)
		if err != nil {
			return "", authorization.Node{}, err
		}
		if err = evaluator.Search(ctx, directory); err != nil {
			return "", authorization.Node{}, err
		}
		if component == "." {
			continue
		}
		if component == ".." {
			if current == capture.Root {
				if capture.FilesystemRoot {
					continue
				}
				return "", authorization.Node{}, ErrAuthority
			}
			current = path.Dir(current)
			continue
		}
		next, record, ok, err := lookupPathComponent(records, current, component, directory.Mount)
		if err != nil {
			return "", authorization.Node{}, err
		}
		if !ok {
			return "", authorization.Node{}, missing()
		}
		if record.Kind == "symlink" {
			links++
			if links > 32 {
				return "", authorization.Node{}, syscall.ELOOP
			}
			if strings.IndexByte(record.Target, 0) >= 0 {
				return "", authorization.Node{}, metatransport.ErrInvalid
			}
			if record.Target == "" {
				return "", authorization.Node{}, syscall.ENOENT
			}
			// lookup removes only terminal slashes before link expansion. Preserve
			// internal separators for namei's linklen + ni_pathlen budget.
			remaining := strings.TrimRight(strings.Join(parts, "/"), "/")
			expanded := len(record.Target) + 1
			if remaining != "" {
				expanded += len(remaining) + 1
			}
			if expanded > limit {
				return "", authorization.Node{}, syscall.ENAMETOOLONG
			}
			if strings.HasPrefix(record.Target, "/") {
				if !capture.FilesystemRoot {
					return "", authorization.Node{}, ErrAuthority
				}
				current = capture.Root
			}
			// macOS 15 loses caller terminal slashes when the final component
			// expands a symlink; 26/27 preserve the directory requirement. Slashes
			// belonging to the link target itself are parsed normally below.
			if profile == osversion.MacOS15 && remaining == "" {
				parts = nil
			}
			parts = append(strings.Split(record.Target, "/"), parts...)
			continue
		}
		current = next
	}
	leaf, err := node(current)
	if err != nil {
		return "", authorization.Node{}, err
	}
	if records[current].Kind == "directory" {
		return "", authorization.Node{}, syscall.EISDIR
	}
	if records[current].Kind != "file" || leaf.Stat.Mode&0170000 != 0100000 {
		return "", authorization.Node{}, metatransport.ErrInvalid
	}
	return current, leaf, nil
}

// CapturedPathObservation reads source-security presence from an extraction that
// retained complete attribute enumeration. The caller supplies the separately
// observed logical mount and identity; this function never derives them from the
// carrier's receiving host. Bind the result using NewPathContext before use.
func CapturedPathObservation(ctx context.Context, store *metatransport.Store, record metatransport.Record, mount authorization.Mount, identity uint64) (PathObservation, error) {
	if store == nil || mount.Identity == "" || mount.Filesystem == "" {
		return PathObservation{}, ErrAuthority
	}
	value, captured, err := store.ObservedSourceAttribute(ctx, record, "com.apple.system.Security")
	if err != nil {
		return PathObservation{}, err
	}
	if !captured {
		return PathObservation{}, ErrAuthority
	}
	state := authorization.SecurityAbsent
	if value != nil {
		state = authorization.SecurityPresent
	}
	return PathObservation{Security: state, Mount: mount, Identity: identity}, nil
}
