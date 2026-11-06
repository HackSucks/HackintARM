package cli

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v2/internal/tools"
)

func TestProjectionJSONCarriesNativeOutcome(t *testing.T) {
	rows := projectionJSON([]tools.ProjectionResult{
		{Path: "file", Field: "xattr", Status: tools.ProjectionApplied, Verified: true},
		{Path: "file", Field: "acl", Status: tools.ProjectionRetained, Err: errors.New("native ACL unavailable")},
	})
	encoded, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"error":"native ACL unavailable"`) || rows[0]["verified"] != true || rows[1]["verified"] != false {
		t.Fatalf("native result lost: %s", encoded)
	}
	if _, ok := rows[0]["error"]; ok {
		t.Fatal("successful operation reports error")
	}
	empty, err := json.Marshal(projectionJSON(nil))
	if err != nil || string(empty) != "[]" {
		t.Fatalf("empty report: %s %v", empty, err)
	}
}
