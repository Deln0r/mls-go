package tree

import "math/bits"

// NodeIndex identifies a position in the array layout of a ratchet tree
// (RFC 9420 section 7.1). Even indices are leaves, odd indices are parents.
type NodeIndex uint32

// LeafIndex identifies a leaf slot. A LeafIndex of L corresponds to
// NodeIndex(2*L).
type LeafIndex uint32

// ToNode returns the NodeIndex for the leaf.
func (l LeafIndex) ToNode() NodeIndex {
	return NodeIndex(2 * l)
}

// ToLeaf returns the LeafIndex for the node if it is a leaf, and false
// otherwise.
func (n NodeIndex) ToLeaf() (LeafIndex, bool) {
	if n%2 != 0 {
		return 0, false
	}
	return LeafIndex(n / 2), true
}

// IsLeaf reports whether n addresses a leaf.
func (n NodeIndex) IsLeaf() bool {
	return n%2 == 0
}

// Level returns the height of n in the tree. Leaves are at level 0.
//
// Per RFC 9420 section 7.1, level(x) is the number of trailing 1-bits in x's
// binary representation. Equivalently it is the count of trailing zeros of
// x + 1.
func (n NodeIndex) Level() uint32 {
	return uint32(bits.TrailingZeros32(^uint32(n)))
}

// NodeWidth returns the array width (number of nodes) for a tree with the
// given number of leaves. Width is 2*n - 1 for n >= 1, and 0 for n == 0.
func NodeWidth(leafCount uint32) uint32 {
	if leafCount == 0 {
		return 0
	}
	return 2*leafCount - 1
}

// LeafCount returns the number of leaf slots in a tree with the given node
// width. Returns 0 if width is 0.
func LeafCount(width uint32) uint32 {
	if width == 0 {
		return 0
	}
	return (width + 1) / 2
}

// Root returns the NodeIndex of the root of a tree with the given node width.
// Panics on width == 0.
//
// For a left-balanced tree with width w = 2*n - 1, the root sits at index
// 2^(ceil(log2(n))) - 1. In binary terms it is the largest "all ones" value
// that fits in w, equivalently (1 << (bits.Len32(w) - 1)) - 1.
func Root(width uint32) NodeIndex {
	if width == 0 {
		panic("tree: Root of empty tree")
	}
	return NodeIndex((1 << (bits.Len32(width) - 1)) - 1)
}

// Left returns the left child of n. Returns (0, false) if n is a leaf.
func (n NodeIndex) Left() (NodeIndex, bool) {
	l := n.Level()
	if l == 0 {
		return 0, false
	}
	return n ^ NodeIndex(1<<(l-1)), true
}

// Right returns the right child of n. Returns (0, false) if n is a leaf.
func (n NodeIndex) Right() (NodeIndex, bool) {
	l := n.Level()
	if l == 0 {
		return 0, false
	}
	return n ^ NodeIndex(3<<(l-1)), true
}

// Parent returns the parent of n in a tree of the given width. Returns
// (0, false) if n is the root.
func (n NodeIndex) Parent(width uint32) (NodeIndex, bool) {
	if uint32(n) == uint32(Root(width)) {
		return 0, false
	}
	l := n.Level()
	b := NodeIndex(1) << (l + 1)
	return (n &^ b) | (b >> 1), true
}

// Sibling returns n's sibling in a tree of the given width. Returns
// (0, false) if n is the root.
func (n NodeIndex) Sibling(width uint32) (NodeIndex, bool) {
	p, ok := n.Parent(width)
	if !ok {
		return 0, false
	}
	if n < p {
		r, _ := p.Right()
		return r, true
	}
	l, _ := p.Left()
	return l, true
}

// DirectPath returns the nodes between n's parent and the root, inclusive,
// in order. For the root, returns an empty slice.
func (n NodeIndex) DirectPath(width uint32) []NodeIndex {
	if width == 0 {
		return nil
	}
	root := Root(width)
	if uint32(n) == uint32(root) {
		return nil
	}
	var path []NodeIndex
	cur := n
	for {
		p, ok := cur.Parent(width)
		if !ok {
			break
		}
		path = append(path, p)
		cur = p
	}
	return path
}

// Copath returns the siblings of every node on n's direct path. The result
// is parallel to DirectPath: copath[i] is the sibling of the i-th direct-path
// node's predecessor (i.e., the sibling encountered while climbing from n to
// the root).
//
// Concretely: the first copath entry is n's sibling; the next is the sibling
// of n's parent; and so on up to (but not including) the root.
func (n NodeIndex) Copath(width uint32) []NodeIndex {
	if width == 0 {
		return nil
	}
	root := Root(width)
	if uint32(n) == uint32(root) {
		return nil
	}
	var cop []NodeIndex
	cur := n
	for {
		sib, ok := cur.Sibling(width)
		if !ok {
			break
		}
		cop = append(cop, sib)
		p, _ := cur.Parent(width)
		if uint32(p) == uint32(root) {
			break
		}
		cur = p
	}
	return cop
}

// CommonAncestor returns the lowest node that has both x and y in its
// subtree.
func CommonAncestor(x, y NodeIndex) NodeIndex {
	lx, ly := x.Level(), y.Level()
	xn, yn := uint32(x), uint32(y)
	// Bring x and y to the same level by walking the shallower one up.
	for lx < ly {
		xn = parentRaw(xn, lx)
		lx++
	}
	for ly < lx {
		yn = parentRaw(yn, ly)
		ly++
	}
	// Now walk both up until they coincide.
	for xn != yn {
		xn = parentRaw(xn, lx)
		yn = parentRaw(yn, ly)
		lx++
		ly++
	}
	return NodeIndex(xn)
}

// parentRaw computes the parent of node n at level l, ignoring tree width
// (i.e., treating the tree as infinite). Used by CommonAncestor.
func parentRaw(n, l uint32) uint32 {
	b := uint32(1) << (l + 1)
	return (n &^ b) | (b >> 1)
}
