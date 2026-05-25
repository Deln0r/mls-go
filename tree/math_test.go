package tree

import (
	"reflect"
	"testing"
)

func TestLevelLeafAndParent(t *testing.T) {
	// For a tree with 8 leaves, width is 15.
	// Levels: leaves at indices 0,2,4,6,8,10,12,14 are level 0.
	// Indices 1,5,9,13 are level 1; 3,11 are level 2; 7 is level 3.
	wantLevels := map[NodeIndex]uint32{
		0: 0, 1: 1, 2: 0, 3: 2, 4: 0, 5: 1, 6: 0, 7: 3,
		8: 0, 9: 1, 10: 0, 11: 2, 12: 0, 13: 1, 14: 0,
	}
	for n, want := range wantLevels {
		if got := n.Level(); got != want {
			t.Errorf("Level(%d) = %d, want %d", n, got, want)
		}
	}
}

func TestRootForCanonicalWidths(t *testing.T) {
	cases := []struct {
		leaves uint32
		width  uint32
		root   NodeIndex
	}{
		{1, 1, 0},
		{2, 3, 1},
		{4, 7, 3},
		{8, 15, 7},
		{16, 31, 15},
	}
	for _, c := range cases {
		if got := NodeWidth(c.leaves); got != c.width {
			t.Errorf("NodeWidth(%d) = %d, want %d", c.leaves, got, c.width)
		}
		if got := Root(c.width); got != c.root {
			t.Errorf("Root(width=%d) = %d, want %d", c.width, got, c.root)
		}
	}
}

func TestParentChildrenRoundtrip(t *testing.T) {
	// Width 15 (8 leaves). For every non-root node, parent's left/right
	// should include it.
	const width uint32 = 15
	root := Root(width)
	for i := uint32(0); i < width; i++ {
		n := NodeIndex(i)
		if n == root {
			if _, ok := n.Parent(width); ok {
				t.Errorf("Parent(root=%d) reported a parent", n)
			}
			continue
		}
		p, ok := n.Parent(width)
		if !ok {
			t.Fatalf("Parent(%d) returned !ok in width %d", n, width)
		}
		l, lok := p.Left()
		r, rok := p.Right()
		if !lok || !rok {
			t.Fatalf("Parent %d of %d has no children?", p, n)
		}
		if n != l && n != r {
			t.Errorf("Parent(%d) = %d, but children are %d/%d", n, p, l, r)
		}
	}
}

func TestSiblingSymmetric(t *testing.T) {
	const width uint32 = 15
	root := Root(width)
	for i := uint32(0); i < width; i++ {
		n := NodeIndex(i)
		if n == root {
			continue
		}
		s, ok := n.Sibling(width)
		if !ok {
			t.Fatalf("Sibling(%d) returned !ok", n)
		}
		s2, ok := s.Sibling(width)
		if !ok || s2 != n {
			t.Errorf("Sibling(Sibling(%d)) = %d, want %d", n, s2, n)
		}
	}
}

func TestDirectPath(t *testing.T) {
	// For width 7 (4 leaves), leaf 0 (index 0) path is [1, 3].
	want := []NodeIndex{1, 3}
	got := NodeIndex(0).DirectPath(7)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DirectPath(0, width=7) = %v, want %v", got, want)
	}
	// Leaf 1 (index 2) path is [1, 3].
	got = NodeIndex(2).DirectPath(7)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DirectPath(2, width=7) = %v, want %v", got, want)
	}
	// Leaf 2 (index 4) path is [5, 3].
	want = []NodeIndex{5, 3}
	got = NodeIndex(4).DirectPath(7)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DirectPath(4, width=7) = %v, want %v", got, want)
	}
	// Root path is empty.
	if p := NodeIndex(3).DirectPath(7); len(p) != 0 {
		t.Errorf("DirectPath(root) = %v, want []", p)
	}
}

func TestCopath(t *testing.T) {
	// Width 7. Leaf 0's copath is [2, 5]: sibling of 0 is 2, sibling of 1 is 5.
	want := []NodeIndex{2, 5}
	got := NodeIndex(0).Copath(7)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Copath(0, width=7) = %v, want %v", got, want)
	}
	// Leaf 2 (index 4), copath is [6, 1]: sibling of 4 is 6, sibling of 5 is 1.
	want = []NodeIndex{6, 1}
	got = NodeIndex(4).Copath(7)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Copath(4, width=7) = %v, want %v", got, want)
	}
}

func TestDirectPathCopathParallel(t *testing.T) {
	// For any leaf in a width-15 tree, DirectPath and Copath should have the
	// same length, and the i-th copath entry is the sibling of the climb's
	// predecessor.
	const width uint32 = 15
	for leaf := uint32(0); leaf < 8; leaf++ {
		n := LeafIndex(leaf).ToNode()
		dp := n.DirectPath(width)
		cp := n.Copath(width)
		if len(dp) != len(cp) {
			t.Errorf("leaf %d: DirectPath len %d, Copath len %d", leaf, len(dp), len(cp))
		}
	}
}

func TestCommonAncestor(t *testing.T) {
	// Width 7. CommonAncestor(0, 2) = 1; (0, 4) = 3; (4, 6) = 5.
	cases := []struct {
		x, y NodeIndex
		want NodeIndex
	}{
		{0, 2, 1},
		{0, 4, 3},
		{0, 6, 3},
		{2, 4, 3},
		{4, 6, 5},
		{1, 5, 3},
		{0, 0, 0},
	}
	for _, c := range cases {
		if got := CommonAncestor(c.x, c.y); got != c.want {
			t.Errorf("CommonAncestor(%d, %d) = %d, want %d", c.x, c.y, got, c.want)
		}
	}
}

func TestLeafIndexConversions(t *testing.T) {
	for l := uint32(0); l < 8; l++ {
		n := LeafIndex(l).ToNode()
		if !n.IsLeaf() {
			t.Errorf("LeafIndex(%d).ToNode() = %d not a leaf", l, n)
		}
		back, ok := n.ToLeaf()
		if !ok || uint32(back) != l {
			t.Errorf("ToLeaf(%d) = (%d, %v), want (%d, true)", n, back, ok, l)
		}
	}
	for _, n := range []NodeIndex{1, 3, 5, 7, 9, 11, 13} {
		if n.IsLeaf() {
			t.Errorf("%d should not be a leaf", n)
		}
		if _, ok := n.ToLeaf(); ok {
			t.Errorf("ToLeaf(%d) should fail", n)
		}
	}
}
