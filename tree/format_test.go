package tree

import (
	"bytes"
	"testing"

	"github.com/Deln0r/mls-go/crypto"
	"github.com/Deln0r/mls-go/encoding/mlstls"
)

func TestCredentialBasicRoundtrip(t *testing.T) {
	in := BasicCredential([]byte("alice"))
	wire, err := mlstls.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Credential
	if err := mlstls.Unmarshal(wire, &out); err != nil {
		t.Fatal(err)
	}
	if out.Type != CredentialBasic || !bytes.Equal(out.Identity, []byte("alice")) {
		t.Fatalf("roundtrip mismatch: %+v", out)
	}
}

func TestCredentialUnsupportedTypeRejected(t *testing.T) {
	in := Credential{Type: CredentialX509, Identity: []byte("cert-bytes")}
	if _, err := mlstls.Marshal(in); err == nil {
		t.Fatalf("X509 credential should not encode while only basic is wired")
	}
}

func TestCapabilitiesRoundtripEmpty(t *testing.T) {
	in := Capabilities{}
	wire, err := mlstls.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Capabilities
	if err := mlstls.Unmarshal(wire, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Versions) != 0 || len(out.Ciphersuites) != 0 {
		t.Fatalf("expected all-empty roundtrip, got %+v", out)
	}
}

func TestCapabilitiesRoundtripPopulated(t *testing.T) {
	in := Capabilities{
		Versions:     []ProtocolVersion{ProtocolVersionMLS10},
		Ciphersuites: []uint16{uint16(crypto.CiphersuiteMTI)},
		Extensions:   []ExtensionType{1, 2, 3},
		Proposals:    []ProposalType{ProposalAdd, ProposalRemove},
		Credentials:  []CredentialType{CredentialBasic},
	}
	wire, err := mlstls.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Capabilities
	if err := mlstls.Unmarshal(wire, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Versions) != 1 || out.Versions[0] != ProtocolVersionMLS10 {
		t.Errorf("Versions mismatch: %v", out.Versions)
	}
	if len(out.Proposals) != 2 || out.Proposals[0] != ProposalAdd || out.Proposals[1] != ProposalRemove {
		t.Errorf("Proposals mismatch: %v", out.Proposals)
	}
	if len(out.Credentials) != 1 || out.Credentials[0] != CredentialBasic {
		t.Errorf("Credentials mismatch: %v", out.Credentials)
	}
}

func TestLifetimeRoundtrip(t *testing.T) {
	in := Lifetime{NotBefore: 100, NotAfter: 200}
	wire, err := mlstls.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Lifetime
	if err := mlstls.Unmarshal(wire, &out); err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("Lifetime roundtrip mismatch: %+v vs %+v", out, in)
	}
}

func makeLeaf(source LeafNodeSource) *LeafNode {
	l := &LeafNode{
		EncryptionKey: bytes.Repeat([]byte{0x11}, crypto.HPKEPublicKeySize),
		SignatureKey:  bytes.Repeat([]byte{0x22}, crypto.SignaturePublicKeySize),
		Credential:    BasicCredential([]byte("alice")),
		Capabilities:  Capabilities{Versions: []ProtocolVersion{ProtocolVersionMLS10}},
		Source:        source,
		Signature:     bytes.Repeat([]byte{0x33}, crypto.SignatureSize),
	}
	switch source {
	case LeafNodeSourceKeyPackage:
		l.Lifetime = Lifetime{NotBefore: 1, NotAfter: 2}
	case LeafNodeSourceCommit:
		l.ParentHash = bytes.Repeat([]byte{0x44}, crypto.HashSize)
	}
	return l
}

func TestLeafNodeRoundtripAllSources(t *testing.T) {
	for _, src := range []LeafNodeSource{
		LeafNodeSourceKeyPackage,
		LeafNodeSourceUpdate,
		LeafNodeSourceCommit,
	} {
		in := makeLeaf(src)
		wire, err := mlstls.Marshal(in)
		if err != nil {
			t.Fatalf("source %d marshal: %v", src, err)
		}
		var out LeafNode
		if err := mlstls.Unmarshal(wire, &out); err != nil {
			t.Fatalf("source %d unmarshal: %v", src, err)
		}
		if out.Source != src {
			t.Errorf("source mismatch: got %d, want %d", out.Source, src)
		}
		if !bytes.Equal(out.EncryptionKey, in.EncryptionKey) {
			t.Errorf("source %d: encryption_key mismatch", src)
		}
		if !bytes.Equal(out.Signature, in.Signature) {
			t.Errorf("source %d: signature mismatch", src)
		}
		switch src {
		case LeafNodeSourceKeyPackage:
			if out.Lifetime != in.Lifetime {
				t.Errorf("Lifetime mismatch")
			}
		case LeafNodeSourceCommit:
			if !bytes.Equal(out.ParentHash, in.ParentHash) {
				t.Errorf("ParentHash mismatch")
			}
		}
	}
}

func TestLeafNodeTBSAddsContextForUpdateAndCommit(t *testing.T) {
	leafKP := makeLeaf(LeafNodeSourceKeyPackage)
	leafCommit := makeLeaf(LeafNodeSourceCommit)

	eKP := mlstls.NewEncoder()
	if err := leafKP.MarshalLeafTBS(eKP, []byte("grp"), 7); err != nil {
		t.Fatal(err)
	}
	eCommit := mlstls.NewEncoder()
	if err := leafCommit.MarshalLeafTBS(eCommit, []byte("grp"), 7); err != nil {
		t.Fatal(err)
	}

	// LeafNodeTBS for commit must include the group_id + leaf_index suffix
	// so it should be strictly longer than the key_package variant.
	if !(len(eCommit.Bytes()) > len(eKP.Bytes())) {
		t.Errorf("commit-source LeafNodeTBS should be larger than key_package: %d vs %d",
			len(eCommit.Bytes()), len(eKP.Bytes()))
	}

	// Same commit leaf with different leaf_index should give different bytes.
	other := mlstls.NewEncoder()
	if err := leafCommit.MarshalLeafTBS(other, []byte("grp"), 8); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(eCommit.Bytes(), other.Bytes()) {
		t.Errorf("LeafNodeTBS should differ when leaf_index differs")
	}
}

func TestParentNodeRoundtrip(t *testing.T) {
	in := &ParentNode{
		EncryptionKey:  bytes.Repeat([]byte{0xAA}, crypto.HPKEPublicKeySize),
		ParentHash:     bytes.Repeat([]byte{0xBB}, crypto.HashSize),
		UnmergedLeaves: []LeafIndex{3, 5, 8},
	}
	wire, err := mlstls.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out ParentNode
	if err := mlstls.Unmarshal(wire, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.EncryptionKey, in.EncryptionKey) ||
		!bytes.Equal(out.ParentHash, in.ParentHash) ||
		len(out.UnmergedLeaves) != 3 {
		t.Fatalf("ParentNode roundtrip mismatch: %+v", out)
	}
}
