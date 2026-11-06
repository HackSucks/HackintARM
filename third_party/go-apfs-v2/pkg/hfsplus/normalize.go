package hfsplus

import "github.com/deploymenttheory/go-apfs-v2/internal/nameunicode"

// normalizeName uses HFS's frozen Unicode3.2 BMP decomposition and ordering.
// Current Unicode NFD would incorrectly change newer and supplementary names.
func normalizeName(name string) string { return nameunicode.HFS(name) }
