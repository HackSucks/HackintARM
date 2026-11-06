package hostdata

// PathMetadata is one path observation. Native capture obtains all fields from
// the same statx response. Captured providers must associate logical metadata
// with the observed source object rather than synthesize Darwin account or
// process state from the receiving host.
type PathMetadata struct {
	State    MetadataState
	Identity LinkIdentity
	Size     int64
}
