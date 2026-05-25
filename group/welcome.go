package group

import (
	"errors"
	"fmt"

	"github.com/Deln0r/mls-go/crypto"
	"github.com/Deln0r/mls-go/encoding/mlstls"
	"github.com/Deln0r/mls-go/tree"
)

// GroupInfo is the post-commit snapshot a joiner needs to align their local
// state with the committer. It is delivered alongside the per-recipient
// HPKE-sealed GroupSecrets inside a Welcome.
type GroupInfo struct {
	Context         GroupContext
	NewLeafIndex    tree.LeafIndex
	TreeSnapshot    []*tree.Node
	ConfirmationTag []byte
}

// GroupSecrets is the per-recipient payload inside a Welcome. It carries
// the joiner_secret that lets the recipient run the joiner-side key
// schedule.
type GroupSecrets struct {
	JoinerSecret []byte
}

// EncryptedGroupSecrets is one HPKE-sealed envelope addressed to a new
// joiner's KeyPackage init_key.
type EncryptedGroupSecrets struct {
	// KeyPackageRef identifies which recipient this envelope is for via
	// RefHash("KeyPackage Reference", canonical_keypackage_bytes). The
	// canonical serialization is the flat concatenation of the KeyPackage
	// public fields under the mlstls codec.
	KeyPackageRef []byte
	Enc           []byte
	Ciphertext    []byte
}

// Welcome is the message a committer hands to each new joiner.
type Welcome struct {
	Envelopes []EncryptedGroupSecrets
	GroupInfo GroupInfo
}

// keyPackageRefHash computes a stable identifier for a KeyPackage so
// EncryptedGroupSecrets can route to the right recipient.
func keyPackageRefHash(kp KeyPackage) ([]byte, error) {
	e := mlstls.NewEncoder()
	if err := e.WriteOpaque(kp.InitKey); err != nil {
		return nil, err
	}
	if err := e.WriteOpaque(kp.SignatureKey); err != nil {
		return nil, err
	}
	if err := e.WriteOpaque(kp.Identity); err != nil {
		return nil, err
	}
	return crypto.RefHash("KeyPackage Reference", e.Bytes())
}

// sealGroupSecrets HPKE-seals the joiner_secret to a recipient's init_key.
// info is empty per RFC 9420 section 12.4.3 ("the info argument to the HPKE
// SealBase function is ... empty"). The committer's group context travels
// separately in GroupInfo, not as HPKE info.
func sealGroupSecrets(initKey crypto.HPKEPublicKey, joinerSecret []byte) (enc, ct []byte, err error) {
	e := mlstls.NewEncoder()
	if err := e.WriteOpaque(joinerSecret); err != nil {
		return nil, nil, err
	}
	return crypto.HPKESealBase(initKey, nil, nil, e.Bytes())
}

// openGroupSecrets reverses sealGroupSecrets.
func openGroupSecrets(initPriv crypto.HPKEPrivateKey, enc, ct []byte) (*GroupSecrets, error) {
	pt, err := crypto.HPKEOpenBase(initPriv, enc, nil, nil, ct)
	if err != nil {
		return nil, fmt.Errorf("group: openGroupSecrets HPKE: %w", err)
	}
	d := mlstls.NewDecoder(pt)
	js, err := d.ReadOpaque()
	if err != nil {
		return nil, fmt.Errorf("group: openGroupSecrets decode: %w", err)
	}
	if !d.Empty() {
		return nil, errors.New("group: openGroupSecrets trailing bytes")
	}
	return &GroupSecrets{JoinerSecret: append([]byte(nil), js...)}, nil
}

// snapshotTree returns a deep copy of the tree's array so a Welcome
// recipient can reconstruct an identical ratchet tree.
func snapshotTree(t *tree.Tree) []*tree.Node {
	out := make([]*tree.Node, t.Width())
	for i := uint32(0); i < t.Width(); i++ {
		n := t.At(tree.NodeIndex(i))
		if n.IsBlank() {
			continue
		}
		copyNode := &tree.Node{}
		if n.Leaf != nil {
			leaf := *n.Leaf
			leaf.EncryptionKey = append(crypto.HPKEPublicKey(nil), n.Leaf.EncryptionKey...)
			leaf.SignatureKey = append(crypto.SignaturePublicKey(nil), n.Leaf.SignatureKey...)
			leaf.Credential = tree.BasicCredential(n.Leaf.Credential.Identity)
			leaf.ParentHash = append([]byte(nil), n.Leaf.ParentHash...)
			leaf.Signature = append([]byte(nil), n.Leaf.Signature...)
			copyNode.Leaf = &leaf
		}
		if n.Parent != nil {
			parent := *n.Parent
			parent.EncryptionKey = append(crypto.HPKEPublicKey(nil), n.Parent.EncryptionKey...)
			parent.ParentHash = append([]byte(nil), n.Parent.ParentHash...)
			parent.UnmergedLeaves = append([]tree.LeafIndex(nil), n.Parent.UnmergedLeaves...)
			copyNode.Parent = &parent
		}
		out[i] = copyNode
	}
	return out
}

// rebuildTree restores a tree from a snapshot produced by snapshotTree.
func rebuildTree(snap []*tree.Node) (*tree.Tree, error) {
	return tree.FromNodes(snap)
}
