package imageacl

import (
	"bytes"
	"fmt"
	"io/fs"

	"github.com/deploymenttheory/go-apfs-v2/pkg/hostdata"
)

// bind validates the complete graph before selecting a target and all aliases.
func bind[T comparable](root, target T, read func(T, bool) (Node[T], error)) ([]T, map[T]Node[T], Node[T], error) {
	var zero T
	if root == zero || target == zero {
		return nil, nil, Node[T]{}, fs.ErrInvalid
	}
	nodes := map[T]Node[T]{}
	stack := []T{root}
	for len(stack) > 0 {
		entry := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, exists := nodes[entry]; entry == zero || exists {
			return nil, nil, Node[T]{}, fmt.Errorf("image ACL: nil, repeated or cyclic entry: %w", fs.ErrInvalid)
		}
		node, err := read(entry, entry == root)
		if err != nil {
			return nil, nil, Node[T]{}, err
		}
		nodes[entry] = node
		stack = append(stack, node.Children...)
	}
	destination, found := nodes[target]
	if !found {
		return nil, nil, Node[T]{}, fs.ErrNotExist
	}
	aliases := []T{target}
	if destination.LinkGroup != 0 && destination.Mode&0170000 == 0100000 {
		for entry, node := range nodes {
			if entry == target || node.Mode&0170000 != 0100000 || node.LinkGroup != destination.LinkGroup {
				continue
			}
			a, ap := destination.Xattrs[hostdata.SecurityName]
			b, bp := node.Xattrs[hostdata.SecurityName]
			if node.UID != destination.UID || node.GID != destination.GID || node.Mode != destination.Mode || ap != bp || !bytes.Equal(a, b) {
				return nil, nil, Node[T]{}, fmt.Errorf("image ACL: conflicting hard-link security: %w", fs.ErrInvalid)
			}
			aliases = append(aliases, entry)
		}
	}
	return aliases, nodes, destination, nil
}
