package hostdata

// ImageMetadata is an image's metadata snapshot, independent of the Go host.
// Mode contains Unix type and permission bits, not fs.FileMode encoding. Times
// is always non-nil after successful capture and owns its storage. LinkID is the
// resolved inode/catalog identifier: aliases share it within the same immutable
// volume. IDs from different volumes must never be compared as link identities.
// Raw security and extended attributes remain available through the image's
// Xattrs API; this snapshot does not read those values or authorize host writes.
type ImageMetadata struct {
	UID, GID, Mode, BSDFlags uint32
	Times                    *FileTimes
	LinkID                   uint64
}

// ImageMetadataFS captures metadata without following the final symlink. Names
// follow fs.ValidPath; "." selects the root. The image must remain immutable
// while capturing metadata and subsequently reading its data and attributes.
type ImageMetadataFS interface {
	Metadata(name string) (ImageMetadata, error)
}
