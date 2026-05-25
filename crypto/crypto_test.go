package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func TestExpandWithLabelDeterministic(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAA}, HashSize)
	a, err := ExpandWithLabel(secret, "joiner", []byte("ctx"), 42)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ExpandWithLabel(secret, "joiner", []byte("ctx"), 42)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("ExpandWithLabel not deterministic")
	}
	if len(a) != 42 {
		t.Fatalf("ExpandWithLabel length: got %d, want 42", len(a))
	}

	c, err := ExpandWithLabel(secret, "joiner", []byte("ctx2"), 42)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, c) {
		t.Fatalf("ExpandWithLabel context did not affect output")
	}
	d, err := ExpandWithLabel(secret, "other", []byte("ctx"), 42)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, d) {
		t.Fatalf("ExpandWithLabel label did not affect output")
	}
}

func TestDeriveSecretLength(t *testing.T) {
	secret := bytes.Repeat([]byte{0xBB}, HashSize)
	out, err := DeriveSecret(secret, "epoch")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != HashSize {
		t.Fatalf("DeriveSecret length: got %d, want %d", len(out), HashSize)
	}
}

func TestDeriveTreeSecretGenerationVaries(t *testing.T) {
	secret := bytes.Repeat([]byte{0xCC}, HashSize)
	a, err := DeriveTreeSecret(secret, "node", 0, HashSize)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveTreeSecret(secret, "node", 1, HashSize)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatalf("DeriveTreeSecret generation did not affect output")
	}
}

func TestRefHashDistinct(t *testing.T) {
	a, err := RefHash("KeyPackage", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := RefHash("KeyPackage", []byte("world"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatalf("RefHash collision on different values")
	}
	c, err := RefHash("Proposal", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, c) {
		t.Fatalf("RefHash collision on different labels")
	}
	if len(a) != HashSize {
		t.Fatalf("RefHash length: got %d, want %d", len(a), HashSize)
	}
}

func TestMACVerify(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, HashSize)
	tag := MAC(key, []byte("confirmed"))
	if !MACEqual(tag, MAC(key, []byte("confirmed"))) {
		t.Fatalf("MAC roundtrip mismatch")
	}
	if MACEqual(tag, MAC(key, []byte("confirme!"))) {
		t.Fatalf("MAC accepted modified content")
	}
}

func TestAEADRoundtrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, AEADKeySize)
	nonce := bytes.Repeat([]byte{0x33}, AEADNonceSize)
	aad := []byte("group context")
	pt := []byte("Welcome, Bob")

	ct, err := AEADSeal(key, nonce, aad, pt)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != len(pt)+AEADTagSize {
		t.Fatalf("ciphertext length: got %d, want %d", len(ct), len(pt)+AEADTagSize)
	}

	got, err := AEADOpen(key, nonce, aad, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("AEAD roundtrip mismatch: got %q, want %q", got, pt)
	}

	// Tamper aad.
	if _, err := AEADOpen(key, nonce, []byte("other ctx"), ct); err == nil {
		t.Fatalf("AEAD open accepted modified AAD")
	}
	// Tamper ct.
	ct[0] ^= 1
	if _, err := AEADOpen(key, nonce, aad, ct); err == nil {
		t.Fatalf("AEAD open accepted modified ciphertext")
	}
}

func TestSignVerifyRoundtrip(t *testing.T) {
	sk, pk, err := GenerateSignatureKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(sk) != SignaturePrivateKeySize || len(pk) != SignaturePublicKeySize {
		t.Fatalf("unexpected key sizes: sk=%d pk=%d", len(sk), len(pk))
	}
	if !bytes.Equal(pk, sk.PublicKey()) {
		t.Fatalf("PublicKey() mismatch")
	}

	msg := []byte("KeyPackage tbs")
	sig, err := SignWithLabel(sk, "KeyPackageTBS", msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("signature size: got %d, want %d", len(sig), SignatureSize)
	}
	if err := VerifyWithLabel(pk, "KeyPackageTBS", msg, sig); err != nil {
		t.Fatalf("VerifyWithLabel: %v", err)
	}
	if err := VerifyWithLabel(pk, "Other", msg, sig); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("VerifyWithLabel accepted wrong label: %v", err)
	}
	if err := VerifyWithLabel(pk, "KeyPackageTBS", []byte("other"), sig); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("VerifyWithLabel accepted wrong message: %v", err)
	}
}

func TestHPKEBaseRoundtrip(t *testing.T) {
	sk, pk, err := GenerateHPKEKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(sk) != HPKEPrivateKeySize || len(pk) != HPKEPublicKeySize {
		t.Fatalf("unexpected HPKE key sizes: sk=%d pk=%d", len(sk), len(pk))
	}
	derivedPk, err := sk.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derivedPk, pk) {
		t.Fatalf("HPKE PublicKey() mismatch")
	}

	info := []byte("Welcome")
	aad := []byte("group context")
	pt := []byte("epoch secret")

	enc, ct, err := HPKESealBase(pk, info, aad, pt)
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) != HPKEPublicKeySize {
		t.Fatalf("enc length: got %d, want %d", len(enc), HPKEPublicKeySize)
	}

	got, err := HPKEOpenBase(sk, enc, info, aad, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("HPKE roundtrip mismatch")
	}

	// Cross-key rejection.
	otherSK, _, err := GenerateHPKEKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := HPKEOpenBase(otherSK, enc, info, aad, ct); err == nil {
		t.Fatalf("HPKE open with wrong key succeeded")
	}

	// Tampered info.
	if _, err := HPKEOpenBase(sk, enc, []byte("Other"), aad, ct); err == nil {
		t.Fatalf("HPKE open with wrong info succeeded")
	}

	// Tampered aad.
	if _, err := HPKEOpenBase(sk, enc, info, []byte("other ctx"), ct); err == nil {
		t.Fatalf("HPKE open with wrong aad succeeded")
	}

	// Tampered ciphertext.
	ctMut := append([]byte{}, ct...)
	ctMut[0] ^= 1
	if _, err := HPKEOpenBase(sk, enc, info, aad, ctMut); err == nil {
		t.Fatalf("HPKE open with tampered ct succeeded")
	}
}

func TestHPKEEncIsEphemeral(t *testing.T) {
	// Same plaintext under same key must yield different (enc, ct) on each
	// call because Encap generates a fresh ephemeral key.
	_, pk, err := GenerateHPKEKey()
	if err != nil {
		t.Fatal(err)
	}
	enc1, ct1, err := HPKESealBase(pk, nil, nil, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	enc2, ct2, err := HPKESealBase(pk, nil, nil, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(enc1, enc2) {
		t.Fatalf("HPKE enc reused: ephemeral key not regenerated")
	}
	if bytes.Equal(ct1, ct2) {
		t.Fatalf("HPKE ct reused")
	}
}
