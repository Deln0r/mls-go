package tree

import (
	"github.com/Deln0r/mls-go/crypto"
	"github.com/Deln0r/mls-go/encoding/mlstls"
)

// ParentNode is the public state of a populated inner ratchet-tree node
// (RFC 9420 section 7.6).
//
//	struct {
//	    HPKEPublicKey encryption_key;
//	    opaque        parent_hash<V>;
//	    LeafIndex     unmerged_leaves<V>;
//	} ParentNode;
type ParentNode struct {
	EncryptionKey  crypto.HPKEPublicKey
	ParentHash     []byte
	UnmergedLeaves []LeafIndex
}

// MarshalMLS encodes a ParentNode.
func (p *ParentNode) MarshalMLS(e *mlstls.Encoder) error {
	if err := e.WriteOpaque(p.EncryptionKey); err != nil {
		return err
	}
	if err := e.WriteOpaque(p.ParentHash); err != nil {
		return err
	}
	return e.WriteVector(func(sub *mlstls.Encoder) error {
		for _, ul := range p.UnmergedLeaves {
			sub.WriteUint32(uint32(ul))
		}
		return nil
	})
}

// UnmarshalMLS decodes a ParentNode.
func (p *ParentNode) UnmarshalMLS(d *mlstls.Decoder) error {
	ek, err := d.ReadOpaque()
	if err != nil {
		return err
	}
	p.EncryptionKey = append(crypto.HPKEPublicKey(nil), ek...)
	ph, err := d.ReadOpaque()
	if err != nil {
		return err
	}
	p.ParentHash = append([]byte(nil), ph...)
	var unmerged []LeafIndex
	if err := d.ReadVector(func(sub *mlstls.Decoder) error {
		for !sub.Empty() {
			v, err := sub.ReadUint32()
			if err != nil {
				return err
			}
			unmerged = append(unmerged, LeafIndex(v))
		}
		return nil
	}); err != nil {
		return err
	}
	p.UnmergedLeaves = unmerged
	return nil
}
