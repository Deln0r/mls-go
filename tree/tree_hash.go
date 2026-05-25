package tree

import (
	"fmt"

	"github.com/Deln0r/mls-go/crypto"
	"github.com/Deln0r/mls-go/encoding/mlstls"
)

// nodeTypeLeaf and nodeTypeParent are the discriminator values used inside
// TreeHashInput (RFC 9420 section 7.8).
const (
	nodeTypeLeaf   uint8 = 1
	nodeTypeParent uint8 = 2
)

// Hash returns the tree hash of t, computed recursively per RFC 9420
// section 7.8.
//
//	struct {
//	    NodeType node_type;
//	    select (Node.node_type) {
//	        case leaf:   LeafNodeHashInput leaf_node_hash_input;
//	        case parent: ParentNodeHashInput parent_node_hash_input;
//	    };
//	} TreeHashInput;
//
//	struct {
//	    uint32 leaf_index;
//	    optional<LeafNode> leaf_node;
//	} LeafNodeHashInput;
//
//	struct {
//	    optional<ParentNode> parent_node;
//	    opaque               left_hash<V>;
//	    opaque               right_hash<V>;
//	} ParentNodeHashInput;
//
// The tree's hash is the recursive hash rooted at Root(width).
func Hash(t *Tree) ([]byte, error) {
	if t.Width() == 0 {
		return crypto.Hash(nil), nil
	}
	return hashSubtree(t, Root(t.Width()))
}

func hashSubtree(t *Tree, idx NodeIndex) ([]byte, error) {
	e := mlstls.NewEncoder()
	if idx.IsLeaf() {
		e.WriteUint8(nodeTypeLeaf)
		if err := encodeLeafHashInput(e, t, idx); err != nil {
			return nil, err
		}
		return crypto.Hash(e.Bytes()), nil
	}

	left, _ := idx.Left()
	right, _ := idx.Right()
	leftHash, err := hashSubtree(t, left)
	if err != nil {
		return nil, err
	}
	rightHash, err := hashSubtree(t, right)
	if err != nil {
		return nil, err
	}

	e.WriteUint8(nodeTypeParent)
	if err := encodeParentHashInput(e, t, idx, leftHash, rightHash); err != nil {
		return nil, err
	}
	return crypto.Hash(e.Bytes()), nil
}

func encodeLeafHashInput(e *mlstls.Encoder, t *Tree, idx NodeIndex) error {
	li, ok := idx.ToLeaf()
	if !ok {
		return fmt.Errorf("tree: encodeLeafHashInput called on parent index %d", idx)
	}
	e.WriteUint32(uint32(li))

	leaf, err := t.Leaf(li)
	if err != nil {
		return err
	}
	if leaf == nil {
		e.WriteUint8(0) // optional absent
		return nil
	}
	e.WriteUint8(1) // optional present
	return leaf.MarshalMLS(e)
}

func encodeParentHashInput(e *mlstls.Encoder, t *Tree, idx NodeIndex, leftHash, rightHash []byte) error {
	pn := t.Parent(idx)
	if pn == nil {
		e.WriteUint8(0)
	} else {
		e.WriteUint8(1)
		if err := pn.MarshalMLS(e); err != nil {
			return err
		}
	}
	if err := e.WriteOpaque(leftHash); err != nil {
		return err
	}
	return e.WriteOpaque(rightHash)
}
