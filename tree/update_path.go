package tree

import (
	"github.com/Deln0r/mls-go/crypto"
	"github.com/Deln0r/mls-go/encoding/mlstls"
)

// UpdatePathNode is one entry in an UpdatePath: the new public key for a
// parent node on the committer's direct path, plus an HPKE ciphertext for
// every recipient in the resolution of that parent's copath sibling
// (RFC 9420 section 7.6).
//
//	struct {
//	    HPKEPublicKey  encryption_key;
//	    HPKECiphertext encrypted_path_secret<V>;
//	} UpdatePathNode;
type UpdatePathNode struct {
	EncryptionKey        crypto.HPKEPublicKey
	EncryptedPathSecrets []crypto.HPKECiphertext
}

// MarshalMLS encodes an UpdatePathNode.
func (n *UpdatePathNode) MarshalMLS(e *mlstls.Encoder) error {
	if err := e.WriteOpaque(n.EncryptionKey); err != nil {
		return err
	}
	return e.WriteVector(func(sub *mlstls.Encoder) error {
		for i := range n.EncryptedPathSecrets {
			if err := n.EncryptedPathSecrets[i].MarshalMLS(sub); err != nil {
				return err
			}
		}
		return nil
	})
}

// UnmarshalMLS decodes an UpdatePathNode.
func (n *UpdatePathNode) UnmarshalMLS(d *mlstls.Decoder) error {
	ek, err := d.ReadOpaque()
	if err != nil {
		return err
	}
	n.EncryptionKey = append(crypto.HPKEPublicKey(nil), ek...)
	var ciphers []crypto.HPKECiphertext
	if err := d.ReadVector(func(sub *mlstls.Decoder) error {
		for !sub.Empty() {
			var c crypto.HPKECiphertext
			if err := c.UnmarshalMLS(sub); err != nil {
				return err
			}
			ciphers = append(ciphers, c)
		}
		return nil
	}); err != nil {
		return err
	}
	n.EncryptedPathSecrets = ciphers
	return nil
}

// UpdatePath is the cryptographic side of a Commit: the committer's new
// LeafNode plus an UpdatePathNode for every parent on the committer's
// direct path.
//
//	struct {
//	    LeafNode       leaf_node;
//	    UpdatePathNode nodes<V>;
//	} UpdatePath;
type UpdatePath struct {
	LeafNode LeafNode
	Nodes    []UpdatePathNode
}

// MarshalMLS encodes an UpdatePath.
func (u *UpdatePath) MarshalMLS(e *mlstls.Encoder) error {
	if err := u.LeafNode.MarshalMLS(e); err != nil {
		return err
	}
	return e.WriteVector(func(sub *mlstls.Encoder) error {
		for i := range u.Nodes {
			if err := u.Nodes[i].MarshalMLS(sub); err != nil {
				return err
			}
		}
		return nil
	})
}

// UnmarshalMLS decodes an UpdatePath.
func (u *UpdatePath) UnmarshalMLS(d *mlstls.Decoder) error {
	if err := u.LeafNode.UnmarshalMLS(d); err != nil {
		return err
	}
	var nodes []UpdatePathNode
	if err := d.ReadVector(func(sub *mlstls.Decoder) error {
		for !sub.Empty() {
			var n UpdatePathNode
			if err := n.UnmarshalMLS(sub); err != nil {
				return err
			}
			nodes = append(nodes, n)
		}
		return nil
	}); err != nil {
		return err
	}
	u.Nodes = nodes
	return nil
}

// NextPathSecret derives the next path_secret in the chain per RFC 9420
// section 7.4:
//
//	path_secret[n+1] = DeriveSecret(path_secret[n], "path")
func NextPathSecret(prev []byte) ([]byte, error) {
	return crypto.DeriveSecret(prev, "path")
}

// HPKEKeysFromPathSecret derives the per-node HPKE keypair from a path
// secret per RFC 9420 section 7.4:
//
//	node_secret = ExpandWithLabel(path_secret, "node", "", KDF.Nh)
//	(node_priv, node_pub) = DeriveKeyPair(node_secret)
func HPKEKeysFromPathSecret(pathSecret []byte) (crypto.HPKEPrivateKey, crypto.HPKEPublicKey, error) {
	nodeSecret, err := crypto.ExpandWithLabel(pathSecret, "node", nil, crypto.HashSize)
	if err != nil {
		return nil, nil, err
	}
	return crypto.DeriveHPKEKey(nodeSecret)
}
