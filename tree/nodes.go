package tree

// Node is an inhabitant of one slot in the ratchet tree array. Exactly one
// of Leaf or Parent is non-nil for a populated slot; both are nil for a
// blank slot.
type Node struct {
	Leaf   *LeafNode
	Parent *ParentNode
}

// IsBlank reports whether the slot is unpopulated.
func (n *Node) IsBlank() bool {
	return n == nil || (n.Leaf == nil && n.Parent == nil)
}
