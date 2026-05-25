package crypto

import (
	"bytes"
	"testing"

	"github.com/Deln0r/mls-go/encoding/mlstls"
)

func TestDeriveHPKEKeyDeterministic(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x42}, HashSize)
	sk1, pk1, err := DeriveHPKEKey(ikm)
	if err != nil {
		t.Fatal(err)
	}
	sk2, pk2, err := DeriveHPKEKey(ikm)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sk1, sk2) || !bytes.Equal(pk1, pk2) {
		t.Fatalf("DeriveHPKEKey not deterministic")
	}
	if len(sk1) != HPKEPrivateKeySize || len(pk1) != HPKEPublicKeySize {
		t.Fatalf("unexpected sizes: sk=%d pk=%d", len(sk1), len(pk1))
	}

	derivedPub, err := sk1.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derivedPub, pk1) {
		t.Fatalf("PublicKey mismatch: derived %x, expected %x", derivedPub, pk1)
	}
}

func TestDeriveHPKEKeyIkmSensitive(t *testing.T) {
	a, _, err := DeriveHPKEKey(bytes.Repeat([]byte{0x01}, HashSize))
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := DeriveHPKEKey(bytes.Repeat([]byte{0x02}, HashSize))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatalf("DeriveHPKEKey gave same output for different ikm")
	}
}

func TestDeriveHPKEKeyEmptyIkmRejected(t *testing.T) {
	if _, _, err := DeriveHPKEKey(nil); err == nil {
		t.Fatalf("DeriveHPKEKey with empty ikm should error")
	}
}

func TestDeriveHPKEKeyUsableForSealOpen(t *testing.T) {
	// The whole point of DeriveHPKEKey is that derived keys are usable for
	// HPKESealBase/HPKEOpenBase exactly like fresh ones.
	ikm := bytes.Repeat([]byte{0x5A}, HashSize)
	sk, pk, err := DeriveHPKEKey(ikm)
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("path secret bound to derived key")
	enc, ct, err := HPKESealBase(pk, nil, nil, pt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := HPKEOpenBase(sk, enc, nil, nil, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("derived key seal/open mismatch")
	}
}

func TestHPKECiphertextRoundtrip(t *testing.T) {
	cases := []HPKECiphertext{
		{KEMOutput: bytes.Repeat([]byte{0xAA}, HPKEPublicKeySize), Ciphertext: []byte("hello")},
		{KEMOutput: nil, Ciphertext: nil},
		{KEMOutput: []byte{0x01}, Ciphertext: bytes.Repeat([]byte{0xFE}, 300)},
	}
	for i, in := range cases {
		wire, err := mlstls.Marshal(in)
		if err != nil {
			t.Fatalf("case %d marshal: %v", i, err)
		}
		var out HPKECiphertext
		if err := mlstls.Unmarshal(wire, &out); err != nil {
			t.Fatalf("case %d unmarshal: %v", i, err)
		}
		if !bytes.Equal(out.KEMOutput, in.KEMOutput) || !bytes.Equal(out.Ciphertext, in.Ciphertext) {
			t.Errorf("case %d roundtrip mismatch:\n  in:  %+v\n  out: %+v", i, in, out)
		}
	}
}
