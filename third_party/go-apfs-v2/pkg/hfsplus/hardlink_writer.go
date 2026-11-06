// Writing hard links.
//
// HFS+ represents several names for one file indirectly. The content lives in
// an "indirect node" file called iNodeNNNN inside a private directory at the
// volume root, and each visible name is a catalog record carrying the 'hlnk'
// file type, the 'hfs+' creator, and the indirect node's catalog id in the BSD
// info's special field. The indirect node puts the number of names in that same
// field.
//
// The shape here follows a volume macOS created rather than the prose: its
// private directory carries the folder-count flag, invisible and name-locked
// Finder flags, a Finder location of (0x4000, 0x4000) and a mode with no
// permission bits at all, and its indirect node holds the file's extended
// attributes as well as its content.
package hfsplus

import (
	"fmt"
	"os"
)

// Private-directory Finder flags: kIsInvisible | kNameLocked.
const privateDirFinderFlags = 0x4000 | 0x1000

// privateDirLocation is the Finder window position macOS gives the private
// directory. It is off-screen, which is part of how the directory stays out of
// sight in tools that honour it.
const privateDirLocation = 0x4000

// buildHardLinks rewrites groups of names that share an inode into HFS+ hard
// links: one indirect node holding the content, and a link record per name.
//
// It runs after flatten, so the visible names already have their catalog ids;
// the private directory and the indirect nodes are appended afterwards and take
// ids after them. Nothing requires the private directory to be id 16, only that
// every id is unique.
func (b *builder) buildHardLinks() {
	groups := map[uint64][]*fileNode{}
	var order []uint64
	for _, n := range b.fileNodes {
		g := n.entry.LinkGroup
		if g == 0 || n.isDir || n.isSymlink {
			continue
		}
		if _, seen := groups[g]; !seen {
			order = append(order, g)
		}
		groups[g] = append(groups[g], n)
	}

	// A group with one name is just a file. Walkers only assign a group when
	// they saw several names, but a caller building a tree by hand might not.
	var linked [][]*fileNode
	for _, g := range order {
		if len(groups[g]) > 1 {
			linked = append(linked, groups[g])
		}
	}
	if len(linked) == 0 {
		return
	}

	private := b.newPrivateDir()

	for _, group := range linked {
		// The first name carries the content into the indirect node; the rest
		// become links to it. Ordering is by the flatten walk, so it is stable.
		first := group[0]
		inode := &fileNode{
			entry:      first.entry,
			cnid:       b.nextCNID,
			parent:     private.cnid,
			isINode:    true,
			linkCount:  uint32(len(group)),
			dataLen:    first.dataLen,
			dataBlocks: first.dataBlocks,
			rsrcLen:    first.rsrcLen,
			rsrcBlocks: first.rsrcBlocks,
			// The attributes belong to the content, not to a name: a reader
			// resolving a link lands on this record and reports them from here.
			attrs: first.attrs,
		}
		b.nextCNID++
		inode.name = fmt.Sprintf("iNode%d", inode.cnid)

		private.children = append(private.children, inode)
		b.allNodes = append(b.allNodes, inode)
		b.fileNodes = append(b.fileNodes, inode)
		b.fileCount++

		for _, n := range group {
			n.isLink = true
			n.linkRef = uint32(inode.cnid)
			// The content moved to the indirect node; a link record has no
			// forks and no attributes of its own.
			n.dataLen, n.dataBlocks = 0, 0
			n.rsrcLen, n.rsrcBlocks = 0, 0
			n.attrs = nil
		}

		// Thread the names into a doubly-linked chain and point the indirect
		// node at its head. Without this fsck_hfs reports "found N pre-Leopard
		// file inodes" and calls the volume corrupt, and macOS reads every
		// linked name as an empty file.
		for i, n := range group {
			if i > 0 {
				n.prevLink = uint32(group[i-1].cnid)
			}
			if i < len(group)-1 {
				n.nextLink = uint32(group[i+1].cnid)
			}
		}
		inode.firstLink = uint32(group[0].cnid)
	}

	// Every name still counts as a file, and the indirect nodes are extra, so
	// fileCount already accounts for both. The private directory is a folder.
	b.folderCount++
}

// newPrivateDir creates the private metadata directory at the volume root.
func (b *builder) newPrivateDir() *fileNode {
	dir := &fileNode{
		entry:  &Entry{Name: metadataDirName, Mode: os.ModeDir},
		name:   metadataDirName,
		cnid:   b.nextCNID,
		parent: b.root.cnid,
		isDir:  true,
	}
	b.nextCNID++
	b.privateDirTime = b.nodeTime(dir)
	b.root.children = append(b.root.children, dir)
	b.allNodes = append(b.allNodes, dir)
	return dir
}

// isPrivateDir reports whether a node is the private metadata directory, which
// is written with its own flags, mode and Finder info rather than the entry's.
func (n *fileNode) isPrivateDir() bool {
	return n.isDir && n.name == metadataDirName
}
