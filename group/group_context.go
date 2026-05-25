package group

import (
	"encoding/binary"

	"github.com/Deln0r/mls-go/crypto"
	"github.com/Deln0r/mls-go/encoding/mlstls"
	"github.com/Deln0r/mls-go/tree"
)

// GroupContext mirrors the RFC 9420 section 8.1 struct that is mixed into
// every label derivation in the key schedule. ProtocolVersion is fixed at
// mls10 and CipherSuite at the supported MTI suite; Extensions are
// currently serialized as an empty vector.
type GroupContext struct {
	GroupID                 []byte
	Epoch                   uint64
	TreeHash                []byte
	ConfirmedTranscriptHash []byte
}

// Marshal serializes GroupContext deterministically for use as the
// "context" argument to ExpandWithLabel in the key schedule.
//
//	struct {
//	    ProtocolVersion version = mls10;
//	    CipherSuite cipher_suite = MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
//	    opaque group_id<V>;
//	    uint64 epoch;
//	    opaque tree_hash<V>;
//	    opaque confirmed_transcript_hash<V>;
//	    Extension extensions<V> = {};
//	} GroupContext;
func (gc GroupContext) Marshal() ([]byte, error) {
	e := mlstls.NewEncoder()
	e.WriteUint16(1) // ProtocolVersion = mls10
	e.WriteUint16(uint16(crypto.CiphersuiteMTI))
	if err := e.WriteOpaque(gc.GroupID); err != nil {
		return nil, err
	}
	e.WriteUint64(gc.Epoch)
	if err := e.WriteOpaque(gc.TreeHash); err != nil {
		return nil, err
	}
	if err := e.WriteOpaque(gc.ConfirmedTranscriptHash); err != nil {
		return nil, err
	}
	if err := e.WriteVarint(0); err != nil { // empty extensions vector
		return nil, err
	}
	return e.Bytes(), nil
}

// TreeHash deterministically hashes the canonical contents of the tree by
// flat-serializing each slot under the mlstls codec and feeding the result
// to SHA-256.
func TreeHash(t *tree.Tree) ([]byte, error) {
	e := mlstls.NewEncoder()
	e.WriteUint32(t.Width())
	for i := uint32(0); i < t.Width(); i++ {
		idx := tree.NodeIndex(i)
		node := t.At(idx)
		if node.IsBlank() {
			e.WriteUint8(0)
			continue
		}
		if node.Leaf != nil {
			e.WriteUint8(1)
			if err := e.WriteOpaque(node.Leaf.EncryptionKey); err != nil {
				return nil, err
			}
			if err := e.WriteOpaque(node.Leaf.SignatureKey); err != nil {
				return nil, err
			}
			if err := e.WriteOpaque(node.Leaf.Identity); err != nil {
				return nil, err
			}
			continue
		}
		e.WriteUint8(2)
		if err := e.WriteOpaque(node.Parent.EncryptionKey); err != nil {
			return nil, err
		}
		if err := e.WriteOpaque(node.Parent.ParentHash); err != nil {
			return nil, err
		}
		e.WriteUint32(uint32(len(node.Parent.UnmergedLeaves)))
		for _, ul := range node.Parent.UnmergedLeaves {
			e.WriteUint32(uint32(ul))
		}
	}
	return crypto.Hash(e.Bytes()), nil
}

// extendTranscriptHash advances the confirmed_transcript_hash chain by
// mixing the prior transcript hash, a fixed "MLS 1.0 commit" tag, the new
// epoch number, and the confirmation_tag, then hashing with SHA-256.
func extendTranscriptHash(prev []byte, newEpoch uint64, confirmationTag []byte) []byte {
	e := mlstls.NewEncoder()
	if err := e.WriteOpaque(prev); err != nil {
		panic("group: extendTranscriptHash WriteOpaque: " + err.Error())
	}
	if err := e.WriteOpaque([]byte("MLS 1.0 commit")); err != nil {
		panic("group: extendTranscriptHash WriteOpaque: " + err.Error())
	}
	var epochOctets [8]byte
	binary.BigEndian.PutUint64(epochOctets[:], newEpoch)
	e.WriteRaw(epochOctets[:])
	if err := e.WriteOpaque(confirmationTag); err != nil {
		panic("group: extendTranscriptHash WriteOpaque: " + err.Error())
	}
	return crypto.Hash(e.Bytes())
}
