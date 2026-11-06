package imagecopy

import (
	"encoding/json"

	"github.com/deploymenttheory/go-apfs-v2/internal/testutil/securitycopy"
	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// Fixture sources use byte-exact filesec records. ACL's text marshaler does not
// round-trip arbitrary flags, so it must not be used as the archive encoding.
func wireSource(s hostdata.SecurityCopySource) securitycopy.Source {
	return securitycopy.Source{Properties: securitycopy.PropertiesFromGo(s.Properties), UID: s.UID, GID: s.GID, Mode: s.Mode}
}
func goSource(s securitycopy.Source) (hostdata.SecurityCopySource, error) {
	p, e := s.Properties.Go()
	return hostdata.SecurityCopySource{Properties: p, UID: s.UID, GID: s.GID, Mode: s.Mode}, e
}
func (c Case) MarshalJSON() ([]byte, error) {
	type alias Case
	return json.Marshal(struct {
		Source securitycopy.Source
		*alias
	}{wireSource(c.Source), (*alias)(&c)})
}
func (c *Case) UnmarshalJSON(b []byte) error {
	type alias Case
	v := struct {
		Source securitycopy.Source
		*alias
	}{alias: (*alias)(c)}
	if e := json.Unmarshal(b, &v); e != nil {
		return e
	}
	var e error
	c.Source, e = goSource(v.Source)
	return e
}

type resultWire struct {
	Source              securitycopy.Source
	Completed, Fallback bool
	Writes              int
	Failures            []hostdata.SecurityCopyFailure
}

func (n NativeCase) MarshalJSON() ([]byte, error) {
	type alias NativeCase
	r := n.GoResult
	return json.Marshal(struct {
		GoResult resultWire
		*alias
	}{resultWire{wireSource(r.Source), r.Completed, r.Fallback, r.Writes, r.Failures}, (*alias)(&n)})
}
func (n *NativeCase) UnmarshalJSON(b []byte) error {
	type alias NativeCase
	v := struct {
		GoResult resultWire
		*alias
	}{alias: (*alias)(n)}
	if e := json.Unmarshal(b, &v); e != nil {
		return e
	}
	s, e := goSource(v.GoResult.Source)
	if e != nil {
		return e
	}
	r := v.GoResult
	n.GoResult = hostdata.SecurityCopyResult{Source: s, Completed: r.Completed, Fallback: r.Fallback, Writes: r.Writes, Failures: r.Failures}
	return nil
}
