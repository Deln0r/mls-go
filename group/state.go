package group

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/Deln0r/mls-go/crypto"
	"github.com/Deln0r/mls-go/tree"
)

// State is a single member's view of a group at a given epoch. It is
// mutated in place by Commit / ProcessWelcome.
type State struct {
	GroupID        []byte
	Epoch          uint64
	Tree           *tree.Tree
	MyLeafIndex    tree.LeafIndex
	MyKey          *KeyPackagePrivate
	MyLeafPriv     crypto.HPKEPrivateKey
	Keys           *EpochKeys
	transcriptHash []byte
	pendingAdds    []KeyPackage
}

// Create initializes a singleton group with the given creator. The creator
// occupies leaf index 0; epoch is 0.
func Create(creator *KeyPackagePrivate, groupID []byte) (*State, error) {
	if creator == nil {
		return nil, errors.New("group: Create called with nil creator")
	}
	if len(groupID) == 0 {
		gid := make([]byte, 16)
		if _, err := rand.Read(gid); err != nil {
			return nil, fmt.Errorf("group: Create groupID: %w", err)
		}
		groupID = gid
	}

	leaf := &tree.LeafNode{
		EncryptionKey: creator.Public.InitKey,
		SignatureKey:  creator.Public.SignatureKey,
		Credential:    tree.BasicCredential(creator.Public.Identity),
		Source:        tree.LeafNodeSourceKeyPackage,
	}
	t := tree.New(leaf)

	th, err := tree.Hash(t)
	if err != nil {
		return nil, err
	}
	confirmedTranscript := make([]byte, crypto.HashSize)
	gc := GroupContext{
		GroupID:                 groupID,
		Epoch:                   0,
		TreeHash:                th,
		ConfirmedTranscriptHash: confirmedTranscript,
	}
	prevInit := make([]byte, crypto.HashSize)
	commitSecret := make([]byte, crypto.HashSize)
	keys, _, err := deriveEpoch(prevInit, commitSecret, gc)
	if err != nil {
		return nil, err
	}

	return &State{
		GroupID:        groupID,
		Epoch:          0,
		Tree:           t,
		MyLeafIndex:    0,
		MyKey:          creator,
		MyLeafPriv:     creator.InitPriv,
		Keys:           keys,
		transcriptHash: confirmedTranscript,
	}, nil
}

// AddMember stages an Add proposal. The KeyPackage's self-signature is
// verified up front; an unsigned or tampered KeyPackage is rejected here
// rather than at Commit time.
func (s *State) AddMember(kp KeyPackage) error {
	if err := kp.Verify(); err != nil {
		return err
	}
	s.pendingAdds = append(s.pendingAdds, kp)
	return nil
}

// Commit finalizes pending Add proposals, advances the epoch, and returns
// one Welcome per newly-joined member.
func (s *State) Commit() ([]*Welcome, error) {
	if len(s.pendingAdds) == 0 {
		return nil, errors.New("group: Commit with no pending proposals")
	}

	joiners := make([]KeyPackage, len(s.pendingAdds))
	copy(joiners, s.pendingAdds)
	s.pendingAdds = nil

	joinerIndices := make([]tree.LeafIndex, len(joiners))
	for i, kp := range joiners {
		li, err := s.Tree.AddLeaf(&tree.LeafNode{
			EncryptionKey: kp.InitKey,
			SignatureKey:  kp.SignatureKey,
			Credential:    tree.BasicCredential(kp.Identity),
			Source:        tree.LeafNodeSourceKeyPackage,
		})
		if err != nil {
			return nil, fmt.Errorf("group: Commit AddLeaf %d: %w", i, err)
		}
		joinerIndices[i] = li
	}

	// Generate the committer's UpdatePath, install the new HPKE keys on
	// the committer's direct path, and pin the committer's new leaf private
	// key into local state. commit_secret is the path_secret at the root of
	// the direct path; for a singleton group (no parents on the path) the
	// spec's convention of an all-zero string applies.
	cp, err := generateCommitterPath(s.Tree, s.MyLeafIndex, s.GroupID, s.MyKey.Public.Identity, s.MyKey.Public.SignatureKey, s.MyKey.SignaturePriv)
	if err != nil {
		return nil, err
	}
	if err := applyCommitterPath(s.Tree, s.MyLeafIndex, cp.UpdatePath); err != nil {
		return nil, err
	}
	s.MyLeafPriv = cp.LeafPrivateKey

	newEpoch := s.Epoch + 1
	th, err := tree.Hash(s.Tree)
	if err != nil {
		return nil, err
	}

	// Extend the confirmed_transcript_hash with a deterministic epoch tag,
	// derive epoch keys against the resulting GroupContext, then compute
	// the confirmation_tag and ship it inside the GroupInfo.
	commitSecret := cp.CommitSecret
	newTranscript := extendTranscriptHash(s.transcriptHash, newEpoch, nil)

	gcNew := GroupContext{
		GroupID:                 s.GroupID,
		Epoch:                   newEpoch,
		TreeHash:                th,
		ConfirmedTranscriptHash: newTranscript,
	}
	keysNew, joinerSecret, err := deriveEpoch(s.Keys.InitSecret, commitSecret, gcNew)
	if err != nil {
		return nil, err
	}
	confirmationTag := crypto.MAC(keysNew.ConfirmationKey, newTranscript)

	// Build Welcomes.
	snap := snapshotTree(s.Tree)
	welcomes := make([]*Welcome, 0, len(joiners))
	for i, kp := range joiners {
		ref, err := keyPackageRefHash(kp)
		if err != nil {
			return nil, err
		}
		enc, ct, err := sealGroupSecrets(kp.InitKey, joinerSecret)
		if err != nil {
			return nil, err
		}
		welcomes = append(welcomes, &Welcome{
			Envelopes: []EncryptedGroupSecrets{{
				KeyPackageRef: ref,
				Enc:           enc,
				Ciphertext:    ct,
			}},
			GroupInfo: GroupInfo{
				Context:         gcNew,
				NewLeafIndex:    joinerIndices[i],
				TreeSnapshot:    snap,
				ConfirmationTag: confirmationTag,
			},
		})
	}

	// Commit committer-side state.
	s.Epoch = newEpoch
	s.Keys = keysNew
	s.transcriptHash = newTranscript

	return welcomes, nil
}

// Join is the joiner-side counterpart to Commit. It consumes a Welcome
// produced for the given KeyPackage and returns the new member's State.
func Join(myKey *KeyPackagePrivate, w *Welcome) (*State, error) {
	if w == nil {
		return nil, errors.New("group: Join called with nil welcome")
	}
	myRef, err := keyPackageRefHash(myKey.Public)
	if err != nil {
		return nil, err
	}
	var env *EncryptedGroupSecrets
	for i := range w.Envelopes {
		if equalBytes(w.Envelopes[i].KeyPackageRef, myRef) {
			env = &w.Envelopes[i]
			break
		}
	}
	if env == nil {
		return nil, errors.New("group: Join: no envelope addressed to this KeyPackage")
	}
	gs, err := openGroupSecrets(myKey.InitPriv, env.Enc, env.Ciphertext)
	if err != nil {
		return nil, err
	}

	t, err := rebuildTree(w.GroupInfo.TreeSnapshot)
	if err != nil {
		return nil, err
	}

	// Verify the LeafNodeTBS signature on any leaf that was installed by a
	// commit (source=commit). The committer's leaf gets signed in
	// generateCommitterPath; refusing to install it on the joiner side
	// without verification would let a tampered snapshot pass.
	for i := uint32(0); i < t.LeafCount(); i++ {
		li := tree.LeafIndex(i)
		leaf, err := t.Leaf(li)
		if err != nil || leaf == nil {
			continue
		}
		if leaf.Source == tree.LeafNodeSourceCommit {
			if err := verifyLeafNode(leaf, w.GroupInfo.Context.GroupID, uint32(li)); err != nil {
				return nil, fmt.Errorf("group: Join: LeafNodeTBS signature invalid for leaf %d: %w", li, err)
			}
		}
	}

	keys, err := deriveEpochFromJoiner(gs.JoinerSecret, w.GroupInfo.Context)
	if err != nil {
		return nil, err
	}

	if !crypto.MACEqual(crypto.MAC(keys.ConfirmationKey, w.GroupInfo.Context.ConfirmedTranscriptHash), w.GroupInfo.ConfirmationTag) {
		return nil, errors.New("group: Join confirmation_tag mismatch")
	}

	return &State{
		GroupID:        append([]byte(nil), w.GroupInfo.Context.GroupID...),
		Epoch:          w.GroupInfo.Context.Epoch,
		Tree:           t,
		MyLeafIndex:    w.GroupInfo.NewLeafIndex,
		MyKey:          myKey,
		MyLeafPriv:     myKey.InitPriv,
		Keys:           keys,
		transcriptHash: append([]byte(nil), w.GroupInfo.Context.ConfirmedTranscriptHash...),
	}, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
