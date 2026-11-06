package hfsplus

// attrFlag describes the attributes actually stored on this catalog node.
// HFS uses the security bit to decide whether ACL lookup is necessary: writing
// the security xattr without it stores bytes that authorization can ignore.
// Use n.attrs rather than Entry.Xattrs so hard-link names stay unmarked and
// the indirect inode that owns their attributes gets both flags. Presence,
// including an empty value, determines the bits; this does not validate ACLs.
func attrFlag(n *fileNode) CatalogFlags {
	if len(n.attrs) > 0 {
		flags := HFSHasAttributesMask
		for _, a := range n.attrs {
			if a.name == "com.apple.system.Security" {
				flags |= HFSHasSecurityMask
				break
			}
		}
		return flags
	}
	return 0
}
