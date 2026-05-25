package tree

import (
	"errors"
	"fmt"
)

// Tree is an array-backed ratchet tree. The Nodes slice has length
// NodeWidth(LeafCount()), even indices are leaf slots, odd indices are
// parent slots. A nil entry indicates a blank slot.
type Tree struct {
	nodes []*Node
}

// New constructs a tree containing a single populated leaf at index 0.
// Width is 1; there are no parent nodes.
func New(creator *LeafNode) *Tree {
	if creator == nil {
		panic("tree: New requires a non-nil creator leaf")
	}
	return &Tree{nodes: []*Node{{Leaf: creator}}}
}

// FromNodes constructs a tree from a snapshot of node slots, validating
// that the width corresponds to a valid left-balanced layout
// (width = 2*n - 1 for some n >= 1). Nil entries are treated as blank
// slots. The returned tree owns its own slice; the caller is free to
// reuse or modify the snapshot afterwards.
func FromNodes(snap []*Node) (*Tree, error) {
	if len(snap) == 0 {
		return nil, fmt.Errorf("tree: FromNodes empty snapshot")
	}
	w := uint32(len(snap))
	if w%2 == 0 {
		return nil, fmt.Errorf("tree: FromNodes width %d is even (must be 2n-1)", w)
	}
	nodes := make([]*Node, w)
	copy(nodes, snap)
	return &Tree{nodes: nodes}, nil
}

// Width returns the current array width.
func (t *Tree) Width() uint32 {
	return uint32(len(t.nodes))
}

// LeafCount returns the number of leaf slots (populated or blank).
func (t *Tree) LeafCount() uint32 {
	return LeafCount(t.Width())
}

// At returns the slot at the given node index. Out-of-range indices panic
// because callers should derive indices from the tree math functions, which
// are bounded by Width().
func (t *Tree) At(idx NodeIndex) *Node {
	if uint32(idx) >= t.Width() {
		panic(fmt.Sprintf("tree: At(%d) out of range, width %d", idx, t.Width()))
	}
	return t.nodes[idx]
}

// Leaf returns the leaf at the given LeafIndex, or nil if the slot is blank.
// Returns an error if the leaf index is out of range.
func (t *Tree) Leaf(li LeafIndex) (*LeafNode, error) {
	if uint32(li) >= t.LeafCount() {
		return nil, fmt.Errorf("tree: leaf %d out of range, leaf count %d", li, t.LeafCount())
	}
	slot := t.nodes[li.ToNode()]
	if slot == nil || slot.Leaf == nil {
		return nil, nil
	}
	return slot.Leaf, nil
}

// SetLeaf replaces the leaf at li.
func (t *Tree) SetLeaf(li LeafIndex, leaf *LeafNode) error {
	if uint32(li) >= t.LeafCount() {
		return fmt.Errorf("tree: SetLeaf %d out of range, leaf count %d", li, t.LeafCount())
	}
	t.nodes[li.ToNode()] = &Node{Leaf: leaf}
	return nil
}

// Parent returns the parent node at the given NodeIndex, or nil if blank.
func (t *Tree) Parent(idx NodeIndex) *ParentNode {
	if uint32(idx) >= t.Width() || idx.IsLeaf() {
		return nil
	}
	slot := t.nodes[idx]
	if slot == nil {
		return nil
	}
	return slot.Parent
}

// SetParent replaces the parent at idx.
func (t *Tree) SetParent(idx NodeIndex, p *ParentNode) error {
	if uint32(idx) >= t.Width() {
		return fmt.Errorf("tree: SetParent %d out of range, width %d", idx, t.Width())
	}
	if idx.IsLeaf() {
		return fmt.Errorf("tree: SetParent at leaf index %d", idx)
	}
	t.nodes[idx] = &Node{Parent: p}
	return nil
}

// BlankParent blanks the slot at idx; idx must be a parent index.
func (t *Tree) BlankParent(idx NodeIndex) error {
	if uint32(idx) >= t.Width() {
		return fmt.Errorf("tree: BlankParent %d out of range", idx)
	}
	if idx.IsLeaf() {
		return fmt.Errorf("tree: BlankParent at leaf index %d", idx)
	}
	t.nodes[idx] = nil
	return nil
}

// BlankLeaf blanks the leaf slot at li.
func (t *Tree) BlankLeaf(li LeafIndex) error {
	if uint32(li) >= t.LeafCount() {
		return fmt.Errorf("tree: BlankLeaf %d out of range", li)
	}
	t.nodes[li.ToNode()] = nil
	return nil
}

// BlankDirectPath blanks every parent on the direct path from from to the
// root. Used after an Add or Remove to invalidate the affected subtree
// secrets (RFC 9420 section 7.3).
func (t *Tree) BlankDirectPath(from NodeIndex) error {
	for _, p := range from.DirectPath(t.Width()) {
		if err := t.BlankParent(p); err != nil {
			return err
		}
	}
	return nil
}

// ErrTreeFull is returned by AddLeaf when no blank slot is available and the
// tree would need to extend but the caller asked for in-place insertion.
var ErrTreeFull = errors.New("tree: no blank leaf available")

// AddLeaf inserts leaf at the lowest blank LeafIndex, extending the tree if
// necessary. The new leaf's direct path is blanked. Returns the LeafIndex
// where the leaf was placed.
func (t *Tree) AddLeaf(leaf *LeafNode) (LeafIndex, error) {
	if leaf == nil {
		return 0, errors.New("tree: AddLeaf called with nil leaf")
	}
	for i := uint32(0); i < t.LeafCount(); i++ {
		l := LeafIndex(i)
		existing, err := t.Leaf(l)
		if err != nil {
			return 0, err
		}
		if existing == nil {
			t.nodes[l.ToNode()] = &Node{Leaf: leaf}
			if err := t.BlankDirectPath(l.ToNode()); err != nil {
				return 0, err
			}
			return l, nil
		}
	}
	// No blank slots: extend.
	li := LeafIndex(t.LeafCount())
	t.extend()
	t.nodes[li.ToNode()] = &Node{Leaf: leaf}
	if err := t.BlankDirectPath(li.ToNode()); err != nil {
		return 0, err
	}
	return li, nil
}

// extend doubles the number of leaf slots. New slots are blank. Used when
// AddLeaf cannot find an existing blank slot.
func (t *Tree) extend() {
	newLeafCount := t.LeafCount() * 2
	if newLeafCount == 0 {
		newLeafCount = 1
	}
	newWidth := NodeWidth(newLeafCount)
	extended := make([]*Node, newWidth)
	copy(extended, t.nodes)
	t.nodes = extended
}

// Resolution implements RFC 9420 section 7.5.
//
//	resolution(x) =
//	    [x] + unmerged_leaves(x)   if x is a non-blank parent
//	    [x]                        if x is a non-blank leaf
//	    []                         if x is a blank leaf
//	    resolution(left) ++ resolution(right)
//	                                if x is a blank parent
//
// The returned slice lists node indices in left-to-right order.
func (t *Tree) Resolution(idx NodeIndex) []NodeIndex {
	width := t.Width()
	if uint32(idx) >= width {
		return nil
	}
	slot := t.nodes[idx]
	if idx.IsLeaf() {
		if slot == nil || slot.Leaf == nil {
			return nil
		}
		return []NodeIndex{idx}
	}
	if slot != nil && slot.Parent != nil {
		out := []NodeIndex{idx}
		for _, ul := range slot.Parent.UnmergedLeaves {
			out = append(out, ul.ToNode())
		}
		return out
	}
	// Blank parent: union of children's resolutions.
	left, _ := idx.Left()
	right, _ := idx.Right()
	return append(t.Resolution(left), t.Resolution(right)...)
}

// PopulatedLeaves returns the leaf indices of all populated leaves in
// ascending order.
func (t *Tree) PopulatedLeaves() []LeafIndex {
	var out []LeafIndex
	for i := uint32(0); i < t.LeafCount(); i++ {
		l := LeafIndex(i)
		ln, err := t.Leaf(l)
		if err == nil && ln != nil {
			out = append(out, l)
		}
	}
	return out
}
