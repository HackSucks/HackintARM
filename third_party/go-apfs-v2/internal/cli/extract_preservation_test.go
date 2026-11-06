package cli

import (
	"strings"
	"testing"
)

func TestExtractMetadataIntentPreflight(t *testing.T) {
	xattrs, preserve, projection, root := extractXattrs, extractPreserveMeta, extractProjectNative, extractMetadataRoot
	t.Cleanup(func() {
		extractXattrs, extractPreserveMeta, extractProjectNative, extractMetadataRoot = xattrs, preserve, projection, root
	})
	for _, state := range [][3]bool{{true, false, false}, {false, true, false}, {true, true, false}, {false, false, true}} {
		extractXattrs, extractPreserveMeta, extractProjectNative, extractMetadataRoot = state[0], state[1], state[2], ""
		err := runExtract(nil, []string{"not-an-image"})
		if exitCodeFor(err) != ExitUsage || !strings.Contains(err.Error(), "--metadata-root") {
			t.Fatal(state, err)
		}
	}
}
