package tree

import (
	"bytes"
	"testing"
)

func TestHashSingleLeaf(t *testing.T) {
	tr := New(leafFor("alice"))
	h, err := Hash(tr)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 32 {
		t.Fatalf("hash length %d, want 32", len(h))
	}

	// Identical tree should yield identical hash.
	tr2 := New(leafFor("alice"))
	h2, err := Hash(tr2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(h, h2) {
		t.Fatalf("Hash not deterministic across identical trees")
	}
}

func TestHashSensitiveToLeafContents(t *testing.T) {
	a := New(leafFor("alice"))
	b := New(leafFor("bob"))
	ha, _ := Hash(a)
	hb, _ := Hash(b)
	if bytes.Equal(ha, hb) {
		t.Fatalf("Hash collision on different leaf identities")
	}
}

func TestHashSensitiveToLeafPosition(t *testing.T) {
	a := New(leafFor("alice"))
	_, _ = a.AddLeaf(leafFor("bob"))

	b := New(leafFor("bob"))
	_, _ = b.AddLeaf(leafFor("alice"))

	ha, _ := Hash(a)
	hb, _ := Hash(b)
	if bytes.Equal(ha, hb) {
		t.Fatalf("Hash should differ when the same leaves are at different positions")
	}
}

func TestHashSensitiveToParentContents(t *testing.T) {
	a := New(leafFor("alice"))
	_, _ = a.AddLeaf(leafFor("bob"))
	_, _ = a.AddLeaf(leafFor("charlie"))
	ha, _ := Hash(a)

	// Populate parent 1 (between leaves 0 and 2) with a non-blank ParentNode.
	b := New(leafFor("alice"))
	_, _ = b.AddLeaf(leafFor("bob"))
	_, _ = b.AddLeaf(leafFor("charlie"))
	_ = b.SetParent(1, &ParentNode{
		EncryptionKey: []byte("populated"),
		ParentHash:    []byte("ph"),
	})
	hb, _ := Hash(b)

	if bytes.Equal(ha, hb) {
		t.Fatalf("Hash should differ when a parent transitions from blank to populated")
	}
}

func TestHashBlankLeafDistinctFromIdentityLeaf(t *testing.T) {
	a := New(leafFor("alice"))
	_, _ = a.AddLeaf(leafFor("bob"))
	_ = a.BlankLeaf(1)

	b := New(leafFor("alice"))
	_, _ = b.AddLeaf(leafFor("bob"))

	ha, _ := Hash(a)
	hb, _ := Hash(b)
	if bytes.Equal(ha, hb) {
		t.Fatalf("blank leaf and populated leaf should hash differently")
	}
}
