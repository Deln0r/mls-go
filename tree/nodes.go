package tree

import "github.com/Deln0r/mls-go/crypto"

// LeafNode carries the public state of a group member. RFC 9420 section 7.2
// defines additional fields (capabilities, extensions, lifetime, signature)
// used for production interop; this struct holds the subset that is read by
// the current tree operations.
type LeafNode struct {
	// EncryptionKey is the HPKE public key under which this leaf accepts
	// group secrets. It starts as the KeyPackage init_key when the leaf is
	// first added and is replaced by the leaf-node encryption key carried in
	// the update path on later commits.
	EncryptionKey crypto.HPKEPublicKey

	// SignatureKey is the long-term Ed25519 public key that signs this
	// leaf's KeyPackage and subsequent leaf-node updates.
	SignatureKey crypto.SignaturePublicKey

	// Identity is the credential payload. A single byte string holds the
	// basic credential value per RFC 9420 section 5.3.1.
	Identity []byte
}

// ParentNode carries the public state of an inner node populated by an
// update path. Per RFC 9420 section 7.6, a populated parent stores an HPKE
// public key, the parent_hash that ties it to its position in the tree, and
// the list of unmerged leaves (leaves that joined under this subtree
// without participating in a key update).
type ParentNode struct {
	EncryptionKey  crypto.HPKEPublicKey
	ParentHash     []byte
	UnmergedLeaves []LeafIndex
}

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
