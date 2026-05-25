package tree

import (
	"bytes"
	"reflect"
	"testing"
)

func leafFor(id string) *LeafNode {
	return &LeafNode{
		EncryptionKey: []byte("ek-" + id),
		SignatureKey:  []byte("sk-" + id),
		Credential:    BasicCredential([]byte(id)),
		Source:        LeafNodeSourceKeyPackage,
	}
}

func TestNewSingleLeaf(t *testing.T) {
	tr := New(leafFor("alice"))
	if tr.Width() != 1 {
		t.Fatalf("Width = %d, want 1", tr.Width())
	}
	if tr.LeafCount() != 1 {
		t.Fatalf("LeafCount = %d, want 1", tr.LeafCount())
	}
	l, err := tr.Leaf(0)
	if err != nil {
		t.Fatal(err)
	}
	if l == nil || !bytes.Equal(l.Credential.Identity, []byte("alice")) {
		t.Fatalf("leaf 0 = %+v, want alice", l)
	}
}

func TestAddLeafGrowsTree(t *testing.T) {
	tr := New(leafFor("alice"))

	li, err := tr.AddLeaf(leafFor("bob"))
	if err != nil {
		t.Fatal(err)
	}
	if li != 1 {
		t.Errorf("bob added at %d, want 1", li)
	}
	if tr.Width() != 3 {
		t.Errorf("after bob, width %d, want 3", tr.Width())
	}

	li, err = tr.AddLeaf(leafFor("charlie"))
	if err != nil {
		t.Fatal(err)
	}
	if li != 2 {
		t.Errorf("charlie added at %d, want 2", li)
	}
	if tr.Width() != 7 {
		t.Errorf("after charlie, width %d, want 7", tr.Width())
	}
	if tr.LeafCount() != 4 {
		t.Errorf("after charlie, leaf count %d, want 4", tr.LeafCount())
	}

	// Slot 3 should be blank.
	l, err := tr.Leaf(3)
	if err != nil {
		t.Fatal(err)
	}
	if l != nil {
		t.Errorf("leaf 3 should be blank, got %+v", l)
	}
}

func TestAddLeafFillsBlankSlot(t *testing.T) {
	tr := New(leafFor("alice"))
	_, _ = tr.AddLeaf(leafFor("bob"))
	_, _ = tr.AddLeaf(leafFor("charlie"))
	// Slot 3 is blank. Remove bob to make slot 1 blank as well.
	if err := tr.BlankLeaf(1); err != nil {
		t.Fatal(err)
	}

	li, err := tr.AddLeaf(leafFor("dave"))
	if err != nil {
		t.Fatal(err)
	}
	if li != 1 {
		t.Errorf("dave added at %d, want 1 (lowest blank)", li)
	}
	if tr.Width() != 7 {
		t.Errorf("width changed to %d, want 7 (filled blank, no extend)", tr.Width())
	}
}

func TestBlankDirectPathOnAdd(t *testing.T) {
	tr := New(leafFor("alice"))
	// Plant a fake parent at index 1, then add bob.
	tr.nodes = append(tr.nodes, &Node{Parent: &ParentNode{EncryptionKey: []byte("dummy")}})
	tr.nodes = append(tr.nodes, nil)
	// Manually pretend width is 3 (already is now). bob inserts at leaf 1.
	_, err := tr.AddLeaf(leafFor("bob"))
	if err != nil {
		t.Fatal(err)
	}
	if p := tr.Parent(1); p != nil {
		t.Errorf("parent at index 1 should have been blanked by Add, got %+v", p)
	}
}

func TestResolutionPopulatedLeaf(t *testing.T) {
	tr := New(leafFor("alice"))
	_, _ = tr.AddLeaf(leafFor("bob"))
	_, _ = tr.AddLeaf(leafFor("charlie"))

	// Resolution of leaf 0 (alice) is [0].
	if got := tr.Resolution(0); !reflect.DeepEqual(got, []NodeIndex{0}) {
		t.Errorf("Resolution(0) = %v, want [0]", got)
	}
	// Resolution of blank leaf 3 (index 6) is [].
	if got := tr.Resolution(6); len(got) != 0 {
		t.Errorf("Resolution(6 blank) = %v, want []", got)
	}
}

func TestResolutionBlankParentUnionsChildren(t *testing.T) {
	tr := New(leafFor("alice"))
	_, _ = tr.AddLeaf(leafFor("bob"))
	_, _ = tr.AddLeaf(leafFor("charlie"))

	// Width 7, root = 3. After three Adds with no path updates, the parents
	// are all blank. Resolution of root should walk the tree and return
	// every populated leaf.
	got := tr.Resolution(3)
	want := []NodeIndex{0, 2, 4}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Resolution(root) = %v, want %v", got, want)
	}
}

func TestResolutionPopulatedParent(t *testing.T) {
	tr := New(leafFor("alice"))
	_, _ = tr.AddLeaf(leafFor("bob"))
	_, _ = tr.AddLeaf(leafFor("charlie"))

	// Populate parent at index 1 (parent of leaves 0, 2). Mark unmerged
	// leaves none. Resolution of node 1 should be just [1].
	_ = tr.SetParent(1, &ParentNode{EncryptionKey: []byte("p1-ek")})
	got := tr.Resolution(1)
	if !reflect.DeepEqual(got, []NodeIndex{1}) {
		t.Errorf("populated parent Resolution(1) = %v, want [1]", got)
	}

	// With an unmerged leaf, Resolution should also include that leaf's node
	// index.
	_ = tr.SetParent(1, &ParentNode{EncryptionKey: []byte("p1-ek"), UnmergedLeaves: []LeafIndex{2}})
	got = tr.Resolution(1)
	if !reflect.DeepEqual(got, []NodeIndex{1, 4}) {
		t.Errorf("populated parent with unmerged Resolution(1) = %v, want [1 4]", got)
	}
}

func TestPopulatedLeaves(t *testing.T) {
	tr := New(leafFor("alice"))
	_, _ = tr.AddLeaf(leafFor("bob"))
	_, _ = tr.AddLeaf(leafFor("charlie"))
	if got := tr.PopulatedLeaves(); !reflect.DeepEqual(got, []LeafIndex{0, 1, 2}) {
		t.Errorf("PopulatedLeaves = %v, want [0 1 2]", got)
	}
	_ = tr.BlankLeaf(1)
	if got := tr.PopulatedLeaves(); !reflect.DeepEqual(got, []LeafIndex{0, 2}) {
		t.Errorf("PopulatedLeaves after blank = %v, want [0 2]", got)
	}
}
