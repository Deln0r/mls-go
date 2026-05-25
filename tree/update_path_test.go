package tree

import (
	"bytes"
	"testing"

	"github.com/Deln0r/mls-go/crypto"
	"github.com/Deln0r/mls-go/encoding/mlstls"
)

func TestUpdatePathNodeRoundtrip(t *testing.T) {
	in := UpdatePathNode{
		EncryptionKey: bytes.Repeat([]byte{0xAB}, crypto.HPKEPublicKeySize),
		EncryptedPathSecrets: []crypto.HPKECiphertext{
			{KEMOutput: bytes.Repeat([]byte{0x01}, crypto.HPKEPublicKeySize), Ciphertext: []byte("first")},
			{KEMOutput: bytes.Repeat([]byte{0x02}, crypto.HPKEPublicKeySize), Ciphertext: []byte("second")},
		},
	}
	wire, err := mlstls.Marshal(&in)
	if err != nil {
		t.Fatal(err)
	}
	var out UpdatePathNode
	if err := mlstls.Unmarshal(wire, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.EncryptionKey, in.EncryptionKey) {
		t.Errorf("EncryptionKey mismatch")
	}
	if len(out.EncryptedPathSecrets) != 2 {
		t.Fatalf("EncryptedPathSecrets len mismatch: %d", len(out.EncryptedPathSecrets))
	}
	if !bytes.Equal(out.EncryptedPathSecrets[0].Ciphertext, []byte("first")) ||
		!bytes.Equal(out.EncryptedPathSecrets[1].Ciphertext, []byte("second")) {
		t.Errorf("Ciphertext content mismatch")
	}
}

func TestUpdatePathRoundtrip(t *testing.T) {
	in := UpdatePath{
		LeafNode: *makeLeaf(LeafNodeSourceCommit),
		Nodes: []UpdatePathNode{
			{EncryptionKey: bytes.Repeat([]byte{0x10}, crypto.HPKEPublicKeySize)},
			{EncryptionKey: bytes.Repeat([]byte{0x20}, crypto.HPKEPublicKeySize)},
		},
	}
	wire, err := mlstls.Marshal(&in)
	if err != nil {
		t.Fatal(err)
	}
	var out UpdatePath
	if err := mlstls.Unmarshal(wire, &out); err != nil {
		t.Fatal(err)
	}
	if out.LeafNode.Source != LeafNodeSourceCommit {
		t.Errorf("LeafNode source mismatch: got %d", out.LeafNode.Source)
	}
	if len(out.Nodes) != 2 {
		t.Fatalf("Nodes len mismatch: %d", len(out.Nodes))
	}
	if !bytes.Equal(out.Nodes[0].EncryptionKey, in.Nodes[0].EncryptionKey) {
		t.Errorf("Node[0] EncryptionKey mismatch")
	}
}

func TestNextPathSecretChain(t *testing.T) {
	p0 := bytes.Repeat([]byte{0x55}, crypto.HashSize)
	p1, err := NextPathSecret(p0)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := NextPathSecret(p1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(p0, p1) || bytes.Equal(p1, p2) {
		t.Fatalf("chain should produce distinct secrets")
	}
	if len(p1) != crypto.HashSize || len(p2) != crypto.HashSize {
		t.Fatalf("path_secret length mismatch")
	}

	// Determinism: same input → same output.
	p1b, _ := NextPathSecret(p0)
	if !bytes.Equal(p1, p1b) {
		t.Fatalf("NextPathSecret not deterministic")
	}
}

func TestHPKEKeysFromPathSecret(t *testing.T) {
	ps := bytes.Repeat([]byte{0x99}, crypto.HashSize)
	sk, pk, err := HPKEKeysFromPathSecret(ps)
	if err != nil {
		t.Fatal(err)
	}
	if len(sk) != crypto.HPKEPrivateKeySize || len(pk) != crypto.HPKEPublicKeySize {
		t.Fatalf("unexpected key sizes")
	}

	// Determinism + the seal/open roundtrip works on the derived key.
	sk2, pk2, _ := HPKEKeysFromPathSecret(ps)
	if !bytes.Equal(sk, sk2) || !bytes.Equal(pk, pk2) {
		t.Fatalf("HPKEKeysFromPathSecret not deterministic")
	}
	enc, ct, err := crypto.HPKESealBase(pk, nil, nil, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := crypto.HPKEOpenBase(sk, enc, nil, nil, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("seal/open mismatch on derived key")
	}
}
