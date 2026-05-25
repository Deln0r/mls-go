package group

import (
	"crypto/rand"
	"fmt"

	"github.com/Deln0r/mls-go/crypto"
	"github.com/Deln0r/mls-go/tree"
)

// committerPath bundles the products of a single UpdatePath derivation:
// the wire-format UpdatePath, the new private state the committer must
// retain (their leaf HPKE private key plus the per-parent path secrets),
// and the commit_secret that feeds into the key schedule.
type committerPath struct {
	UpdatePath     *tree.UpdatePath
	LeafPrivateKey crypto.HPKEPrivateKey
	PathSecrets    [][]byte
	CommitSecret   []byte
}

// generateCommitterPath builds a fresh UpdatePath rooted at the committer's
// leaf, per RFC 9420 section 7.6:
//
//  1. Sample a 32-byte leaf secret. Derive a new HPKE keypair for the
//     committer's leaf via crypto.DeriveHPKEKey.
//
//  2. Compute the path secret chain along the direct path:
//     path_secret[0] = DeriveSecret(leaf_secret, "path")
//     path_secret[i] = DeriveSecret(path_secret[i-1], "path")
//
//  3. For each parent on the direct path, derive its new HPKE keypair via
//     tree.HPKEKeysFromPathSecret and place the public side into the
//     matching UpdatePathNode.
//
//  4. commit_secret is the path_secret at the root of the direct path.
//
// The function does not yet encrypt path secrets to copath resolutions;
// for the current 3-member smoke flow every copath member is an unmerged
// new joiner and learns the schedule through Welcome.joiner_secret rather
// than UpdatePathNode ciphertexts. Wire shape is preserved so external
// readers see a fully-formed UpdatePath.
func generateCommitterPath(t *tree.Tree, committer tree.LeafIndex, identity []byte, signatureKey crypto.SignaturePublicKey) (*committerPath, error) {
	committerNode := committer.ToNode()
	directPath := committerNode.DirectPath(t.Width())

	leafSecret := make([]byte, crypto.HashSize)
	if _, err := rand.Read(leafSecret); err != nil {
		return nil, fmt.Errorf("group: generateCommitterPath leaf_secret: %w", err)
	}
	leafPriv, leafPub, err := crypto.DeriveHPKEKey(leafSecret)
	if err != nil {
		return nil, fmt.Errorf("group: generateCommitterPath leaf key: %w", err)
	}

	pathSecrets := make([][]byte, len(directPath))
	if len(directPath) > 0 {
		first, err := crypto.DeriveSecret(leafSecret, "path")
		if err != nil {
			return nil, err
		}
		pathSecrets[0] = first
		for i := 1; i < len(directPath); i++ {
			next, err := tree.NextPathSecret(pathSecrets[i-1])
			if err != nil {
				return nil, err
			}
			pathSecrets[i] = next
		}
	}

	nodes := make([]tree.UpdatePathNode, len(directPath))
	for i := range directPath {
		_, pub, err := tree.HPKEKeysFromPathSecret(pathSecrets[i])
		if err != nil {
			return nil, err
		}
		nodes[i] = tree.UpdatePathNode{EncryptionKey: pub}
	}

	newLeaf := tree.LeafNode{
		EncryptionKey: leafPub,
		SignatureKey:  signatureKey,
		Credential:    tree.BasicCredential(identity),
		Source:        tree.LeafNodeSourceCommit,
	}

	var commitSecret []byte
	if len(pathSecrets) == 0 {
		commitSecret = make([]byte, crypto.HashSize)
	} else {
		commitSecret = pathSecrets[len(pathSecrets)-1]
	}

	return &committerPath{
		UpdatePath:     &tree.UpdatePath{LeafNode: newLeaf, Nodes: nodes},
		LeafPrivateKey: leafPriv,
		PathSecrets:    pathSecrets,
		CommitSecret:   commitSecret,
	}, nil
}

// applyCommitterPath installs the new public keys carried by an UpdatePath
// into the tree: the committer's leaf gets the new LeafNode, every parent
// on the direct path gets a populated ParentNode with the new HPKE
// encryption key. The direct-path positions are aligned with
// UpdatePath.Nodes by index.
func applyCommitterPath(t *tree.Tree, committer tree.LeafIndex, up *tree.UpdatePath) error {
	if err := t.SetLeaf(committer, &up.LeafNode); err != nil {
		return err
	}
	directPath := committer.ToNode().DirectPath(t.Width())
	if len(directPath) != len(up.Nodes) {
		return fmt.Errorf("group: applyCommitterPath direct path %d != UpdatePath.Nodes %d", len(directPath), len(up.Nodes))
	}
	for i, idx := range directPath {
		pn := &tree.ParentNode{EncryptionKey: up.Nodes[i].EncryptionKey}
		if err := t.SetParent(idx, pn); err != nil {
			return err
		}
	}
	return nil
}
