package tree

import (
	"fmt"

	"github.com/Deln0r/mls-go/crypto"
	"github.com/Deln0r/mls-go/encoding/mlstls"
)

// LeafNode is a member's public state in the ratchet tree
// (RFC 9420 section 7.2).
//
//	struct {
//	    HPKEPublicKey       encryption_key;
//	    SignaturePublicKey  signature_key;
//	    Credential          credential;
//	    Capabilities        capabilities;
//	    LeafNodeSource      leaf_node_source;
//	    select (LeafNode.leaf_node_source) {
//	        case key_package: Lifetime  lifetime;
//	        case update:      struct{};
//	        case commit:      opaque    parent_hash<V>;
//	    };
//	    Extension           extensions<V>;
//	    opaque              signature<V>;
//	} LeafNode;
type LeafNode struct {
	EncryptionKey crypto.HPKEPublicKey
	SignatureKey  crypto.SignaturePublicKey
	Credential    Credential
	Capabilities  Capabilities
	Source        LeafNodeSource
	Lifetime      Lifetime
	ParentHash    []byte
	Extensions    []Extension
	Signature     []byte
}

// MarshalMLS encodes the full LeafNode including the signature.
func (l *LeafNode) MarshalMLS(e *mlstls.Encoder) error {
	if err := l.marshalCore(e); err != nil {
		return err
	}
	return e.WriteOpaque(l.Signature)
}

// UnmarshalMLS decodes a LeafNode written by MarshalMLS.
func (l *LeafNode) UnmarshalMLS(d *mlstls.Decoder) error {
	if err := l.unmarshalCore(d); err != nil {
		return err
	}
	sig, err := d.ReadOpaque()
	if err != nil {
		return err
	}
	l.Signature = append([]byte(nil), sig...)
	return nil
}

// MarshalLeafTBS encodes the to-be-signed form of LeafNode for use with
// crypto.SignWithLabel ("LeafNodeTBS"). It is the same as MarshalMLS up to
// (but not including) the signature, with extra context appended for the
// update / commit sources per RFC 9420 section 7.2:
//
//	select (LeafNode.leaf_node_source) {
//	    case key_package: struct{};
//	    case update:      opaque group_id<V>;
//	                      uint32 leaf_index;
//	    case commit:      opaque group_id<V>;
//	                      uint32 leaf_index;
//	};
//
// groupID and leafIndex are ignored for source=key_package.
func (l *LeafNode) MarshalLeafTBS(e *mlstls.Encoder, groupID []byte, leafIndex uint32) error {
	if err := l.marshalCore(e); err != nil {
		return err
	}
	switch l.Source {
	case LeafNodeSourceKeyPackage:
		return nil
	case LeafNodeSourceUpdate, LeafNodeSourceCommit:
		if err := e.WriteOpaque(groupID); err != nil {
			return err
		}
		e.WriteUint32(leafIndex)
		return nil
	default:
		return fmt.Errorf("tree: LeafNode source %d not supported", l.Source)
	}
}

// marshalCore encodes the common LeafNode fields (everything except the
// signature). Shared by MarshalMLS and MarshalLeafTBS.
func (l *LeafNode) marshalCore(e *mlstls.Encoder) error {
	if err := e.WriteOpaque(l.EncryptionKey); err != nil {
		return err
	}
	if err := e.WriteOpaque(l.SignatureKey); err != nil {
		return err
	}
	if err := l.Credential.MarshalMLS(e); err != nil {
		return err
	}
	if err := l.Capabilities.MarshalMLS(e); err != nil {
		return err
	}
	e.WriteUint8(uint8(l.Source))
	switch l.Source {
	case LeafNodeSourceKeyPackage:
		if err := l.Lifetime.MarshalMLS(e); err != nil {
			return err
		}
	case LeafNodeSourceUpdate:
		// nothing
	case LeafNodeSourceCommit:
		if err := e.WriteOpaque(l.ParentHash); err != nil {
			return err
		}
	default:
		return fmt.Errorf("tree: LeafNode source %d not supported", l.Source)
	}
	return e.WriteVector(func(sub *mlstls.Encoder) error {
		for i := range l.Extensions {
			if err := l.Extensions[i].MarshalMLS(sub); err != nil {
				return err
			}
		}
		return nil
	})
}

// unmarshalCore reads the common LeafNode fields.
func (l *LeafNode) unmarshalCore(d *mlstls.Decoder) error {
	ek, err := d.ReadOpaque()
	if err != nil {
		return err
	}
	l.EncryptionKey = append(crypto.HPKEPublicKey(nil), ek...)
	sk, err := d.ReadOpaque()
	if err != nil {
		return err
	}
	l.SignatureKey = append(crypto.SignaturePublicKey(nil), sk...)
	if err := l.Credential.UnmarshalMLS(d); err != nil {
		return err
	}
	if err := l.Capabilities.UnmarshalMLS(d); err != nil {
		return err
	}
	src, err := d.ReadUint8()
	if err != nil {
		return err
	}
	l.Source = LeafNodeSource(src)
	switch l.Source {
	case LeafNodeSourceKeyPackage:
		if err := l.Lifetime.UnmarshalMLS(d); err != nil {
			return err
		}
	case LeafNodeSourceUpdate:
		// nothing
	case LeafNodeSourceCommit:
		ph, err := d.ReadOpaque()
		if err != nil {
			return err
		}
		l.ParentHash = append([]byte(nil), ph...)
	default:
		return fmt.Errorf("tree: LeafNode source %d not supported", l.Source)
	}
	var exts []Extension
	if err := d.ReadVector(func(sub *mlstls.Decoder) error {
		for !sub.Empty() {
			var x Extension
			if err := x.UnmarshalMLS(sub); err != nil {
				return err
			}
			exts = append(exts, x)
		}
		return nil
	}); err != nil {
		return err
	}
	l.Extensions = exts
	return nil
}
