package crypto_test

import (
	"bytes"
	"fmt"

	"github.com/Deln0r/mls-go/crypto"
)

// ExampleHPKESealBase demonstrates the single-shot HPKE base mode used
// throughout MLS to deliver per-recipient secrets (Welcome envelopes,
// UpdatePath path-secret ciphertexts). The plaintext is bound to the
// recipient public key and to the info / aad parameters; tampering with
// any of them fails the AEAD authentication.
func ExampleHPKESealBase() {
	_, recipientPub, err := crypto.GenerateHPKEKey()
	if err != nil {
		panic(err)
	}

	info := []byte("epoch=1")
	aad := []byte("group_id=demo")
	plaintext := []byte("joiner_secret")

	enc, ct, err := crypto.HPKESealBase(recipientPub, info, aad, plaintext)
	if err != nil {
		panic(err)
	}
	fmt.Printf("kem output size = %d bytes\n", len(enc))
	fmt.Printf("ciphertext = plaintext + AEAD tag (%d + %d bytes)\n",
		len(plaintext), len(ct)-len(plaintext))
	// Output:
	// kem output size = 32 bytes
	// ciphertext = plaintext + AEAD tag (13 + 16 bytes)
}

// ExampleSignWithLabel shows the labeled signature pattern used by every
// MLS-level signature in RFC 9420 section 5.1.6: the signed bytes are
// the opaque-framed label ("MLS 1.0 " + Label) followed by the
// opaque-framed content. Verification rejects mismatched labels even if
// the underlying content bytes are identical.
func ExampleSignWithLabel() {
	sk, pk, err := crypto.GenerateSignatureKey()
	if err != nil {
		panic(err)
	}

	content := []byte("KeyPackage TBS bytes")
	sig, err := crypto.SignWithLabel(sk, "KeyPackageTBS", content)
	if err != nil {
		panic(err)
	}

	ok := crypto.VerifyWithLabel(pk, "KeyPackageTBS", content, sig)
	wrongLabel := crypto.VerifyWithLabel(pk, "Other", content, sig)
	fmt.Println("right label:", ok)
	fmt.Println("wrong label:", wrongLabel)
	// Output:
	// right label: <nil>
	// wrong label: crypto: signature verification failed
}

// ExampleDeriveSecret illustrates the MLS-specific label framing applied
// to HKDF-Expand: the KDFLabel struct carries the requested output
// length, the prefixed label "MLS 1.0 " + label, and the context bytes.
// Outputs are deterministic given the same inputs, so call sites that
// mix in the GroupContext bytes get cryptographic agility for free.
func ExampleDeriveSecret() {
	secret := bytes.Repeat([]byte{0x01}, crypto.HashSize)
	out, err := crypto.DeriveSecret(secret, "epoch")
	if err != nil {
		panic(err)
	}
	fmt.Println("derived length:", len(out))
	// Output:
	// derived length: 32
}
