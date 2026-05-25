package tree

import (
	"fmt"

	"github.com/Deln0r/mls-go/encoding/mlstls"
)

// ProtocolVersion identifies the MLS protocol version (RFC 9420 section 6).
type ProtocolVersion uint16

// ProtocolVersionMLS10 is the only version currently defined.
const ProtocolVersionMLS10 ProtocolVersion = 1

// CredentialType identifies a credential format (RFC 9420 section 5.3).
type CredentialType uint16

const (
	CredentialBasic CredentialType = 1
	CredentialX509  CredentialType = 2
)

// LeafNodeSource identifies how a LeafNode came to occupy its slot
// (RFC 9420 section 7.2).
type LeafNodeSource uint8

const (
	LeafNodeSourceKeyPackage LeafNodeSource = 1
	LeafNodeSourceUpdate     LeafNodeSource = 2
	LeafNodeSourceCommit     LeafNodeSource = 3
)

// ExtensionType is the registry identifier for an MLS extension
// (RFC 9420 section 13).
type ExtensionType uint16

// ProposalType is the registry identifier for an MLS proposal
// (RFC 9420 section 12.1).
type ProposalType uint16

const (
	ProposalAdd     ProposalType = 1
	ProposalUpdate  ProposalType = 2
	ProposalRemove  ProposalType = 3
	ProposalPSK     ProposalType = 4
	ProposalReinit  ProposalType = 5
	ProposalExtJoin ProposalType = 6
	ProposalGCE     ProposalType = 7
)

// Credential is the basic credential payload used by a LeafNode to identify
// its owner (RFC 9420 section 5.3.1).
type Credential struct {
	Type     CredentialType
	Identity []byte
}

// MarshalMLS encodes a Credential. Only the basic credential variant is
// supported; richer types return an error so callers fail loudly.
func (c Credential) MarshalMLS(e *mlstls.Encoder) error {
	e.WriteUint16(uint16(c.Type))
	switch c.Type {
	case CredentialBasic:
		return e.WriteOpaque(c.Identity)
	default:
		return fmt.Errorf("tree: Credential type %d not supported", c.Type)
	}
}

// UnmarshalMLS decodes a Credential.
func (c *Credential) UnmarshalMLS(d *mlstls.Decoder) error {
	t, err := d.ReadUint16()
	if err != nil {
		return err
	}
	c.Type = CredentialType(t)
	switch c.Type {
	case CredentialBasic:
		id, err := d.ReadOpaque()
		if err != nil {
			return err
		}
		c.Identity = append([]byte(nil), id...)
		return nil
	default:
		return fmt.Errorf("tree: Credential type %d not supported", c.Type)
	}
}

// BasicCredential is a convenience constructor.
func BasicCredential(identity []byte) Credential {
	return Credential{Type: CredentialBasic, Identity: append([]byte(nil), identity...)}
}

// Capabilities advertises the protocol features a leaf supports
// (RFC 9420 section 7.2). All five vectors are uint16-element variable-length
// vectors under the MLS wire format.
type Capabilities struct {
	Versions     []ProtocolVersion
	Ciphersuites []uint16
	Extensions   []ExtensionType
	Proposals    []ProposalType
	Credentials  []CredentialType
}

// MarshalMLS encodes Capabilities. Empty vectors are valid.
func (c Capabilities) MarshalMLS(e *mlstls.Encoder) error {
	if err := writeUint16Vector(e, len(c.Versions), func(i int) uint16 { return uint16(c.Versions[i]) }); err != nil {
		return err
	}
	if err := writeUint16Vector(e, len(c.Ciphersuites), func(i int) uint16 { return c.Ciphersuites[i] }); err != nil {
		return err
	}
	if err := writeUint16Vector(e, len(c.Extensions), func(i int) uint16 { return uint16(c.Extensions[i]) }); err != nil {
		return err
	}
	if err := writeUint16Vector(e, len(c.Proposals), func(i int) uint16 { return uint16(c.Proposals[i]) }); err != nil {
		return err
	}
	return writeUint16Vector(e, len(c.Credentials), func(i int) uint16 { return uint16(c.Credentials[i]) })
}

// UnmarshalMLS decodes Capabilities.
func (c *Capabilities) UnmarshalMLS(d *mlstls.Decoder) error {
	vs, err := readUint16Vector(d)
	if err != nil {
		return err
	}
	c.Versions = make([]ProtocolVersion, len(vs))
	for i, v := range vs {
		c.Versions[i] = ProtocolVersion(v)
	}
	if c.Ciphersuites, err = readUint16Vector(d); err != nil {
		return err
	}
	es, err := readUint16Vector(d)
	if err != nil {
		return err
	}
	c.Extensions = make([]ExtensionType, len(es))
	for i, v := range es {
		c.Extensions[i] = ExtensionType(v)
	}
	ps, err := readUint16Vector(d)
	if err != nil {
		return err
	}
	c.Proposals = make([]ProposalType, len(ps))
	for i, v := range ps {
		c.Proposals[i] = ProposalType(v)
	}
	cs, err := readUint16Vector(d)
	if err != nil {
		return err
	}
	c.Credentials = make([]CredentialType, len(cs))
	for i, v := range cs {
		c.Credentials[i] = CredentialType(v)
	}
	return nil
}

// Lifetime bounds when a KeyPackage is considered valid (RFC 9420 section 7.2).
type Lifetime struct {
	NotBefore uint64
	NotAfter  uint64
}

// MarshalMLS encodes a Lifetime as two big-endian uint64.
func (l Lifetime) MarshalMLS(e *mlstls.Encoder) error {
	e.WriteUint64(l.NotBefore)
	e.WriteUint64(l.NotAfter)
	return nil
}

// UnmarshalMLS decodes a Lifetime.
func (l *Lifetime) UnmarshalMLS(d *mlstls.Decoder) error {
	nb, err := d.ReadUint64()
	if err != nil {
		return err
	}
	na, err := d.ReadUint64()
	if err != nil {
		return err
	}
	l.NotBefore = nb
	l.NotAfter = na
	return nil
}

// Extension carries an extension_type plus extension_data per RFC 9420
// section 13. Pre-MVP code creates and parses empty extension vectors only.
type Extension struct {
	Type ExtensionType
	Data []byte
}

// MarshalMLS encodes an Extension.
func (x Extension) MarshalMLS(e *mlstls.Encoder) error {
	e.WriteUint16(uint16(x.Type))
	return e.WriteOpaque(x.Data)
}

// UnmarshalMLS decodes an Extension.
func (x *Extension) UnmarshalMLS(d *mlstls.Decoder) error {
	t, err := d.ReadUint16()
	if err != nil {
		return err
	}
	data, err := d.ReadOpaque()
	if err != nil {
		return err
	}
	x.Type = ExtensionType(t)
	x.Data = append([]byte(nil), data...)
	return nil
}

// writeUint16Vector helper for the Capabilities sub-vectors.
func writeUint16Vector(e *mlstls.Encoder, n int, get func(int) uint16) error {
	return e.WriteVector(func(sub *mlstls.Encoder) error {
		for i := 0; i < n; i++ {
			sub.WriteUint16(get(i))
		}
		return nil
	})
}

// readUint16Vector helper symmetric to writeUint16Vector.
func readUint16Vector(d *mlstls.Decoder) ([]uint16, error) {
	var out []uint16
	err := d.ReadVector(func(sub *mlstls.Decoder) error {
		for !sub.Empty() {
			v, err := sub.ReadUint16()
			if err != nil {
				return err
			}
			out = append(out, v)
		}
		return nil
	})
	return out, err
}
