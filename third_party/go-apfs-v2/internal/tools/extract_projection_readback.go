package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/internal/unixmode"
	"github.com/deploymenttheory/go-apfs-v2/pkg/appledouble"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

type projectionReadback interface {
	Readback(metatransport.Record) (map[string]bool, error)
}

func (p nativeProjection) Readback(r metatransport.Record) (map[string]bool, error) {
	info, err := p.file.Stat()
	if err != nil {
		return nil, err
	}
	var stat *hostdata.StatCopySource
	var security *appledouble.FileSecurity
	if p.heldErr == nil {
		captured, e := p.held.CaptureStat()
		if e != nil {
			return nil, e
		}
		stat = &captured
		for _, a := range r.Attributes {
			if a.Name == hostdata.SecurityName {
				acl, e := p.held.CaptureACL()
				if e != nil {
					return nil, e
				}
				security = acl.Security
				break
			}
		}
	} else if !errors.Is(p.heldErr, errors.ErrUnsupported) {
		return nil, p.heldErr
	}
	return projectionChecks(r, info, stat, security)
}

func projectionChecks(r metatransport.Record, info os.FileInfo, stat *hostdata.StatCopySource, security *appledouble.FileSecurity) (map[string]bool, error) {
	checks := map[string]bool{}
	d := r.Darwin
	if d.Mode != nil {
		checks["mode"] = uint32(unixmode.Permissions(info.Mode(), 0, true)) == *d.Mode&07777
	}
	if d.Modify != nil {
		checks["modify"] = info.ModTime().Equal(*d.Modify)
	}
	if stat != nil {
		if d.UID != nil && d.GID != nil {
			checks["ownership"] = stat.UID == *d.UID && stat.GID == *d.GID
		}
		if d.Access != nil {
			checks["access"] = stat.Times.Access.Equal(*d.Access)
		}
		if d.Birth != nil {
			checks["birth"] = stat.Times.Birth.Equal(*d.Birth)
		}
		if d.Flags != nil {
			checks["flags"] = stat.Flags == (*d.Flags &^ hostdata.UFCompressed)
		}
	}
	if security != nil {
		raw, err := security.MarshalBinary()
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(raw)
		for _, a := range r.Attributes {
			if a.Name == hostdata.SecurityName {
				checks["xattr:"+a.Name] = hex.EncodeToString(sum[:]) == a.Value.SHA256 && int64(len(raw)) == a.Value.Size
			}
		}
	}
	return checks, nil
}
func (e *Extractor) verifyProjectionChecks(r metatransport.Record, checks map[string]bool) {
	for i := range e.projectionResults {
		result := &e.projectionResults[i]
		if result.Path != r.Original || (result.Status != ProjectionApplied && result.Status != ProjectionNormalized) {
			continue
		}
		if equal, known := checks[result.Field]; known {
			result.Verified = equal
			result.Status = ProjectionApplied
			if !equal {
				result.Status = ProjectionNormalized
			}
		}
	}
}
