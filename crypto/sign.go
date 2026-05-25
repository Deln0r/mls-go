package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/Deln0r/mls-go/encoding/mlstls"
)

// SignaturePrivateKey is the Ed25519 private key (64 bytes: 32-byte seed plus
// 32-byte public key, matching the standard library layout).
type SignaturePrivateKey []byte

// SignaturePublicKey is the Ed25519 public key (32 bytes).
type SignaturePublicKey []byte

// GenerateSignatureKey returns a fresh Ed25519 keypair.
func GenerateSignatureKey() (SignaturePrivateKey, SignaturePublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: ed25519.GenerateKey: %w", err)
	}
	return SignaturePrivateKey(priv), SignaturePublicKey(pub), nil
}

// PublicKey returns the public component of an Ed25519 private key.
func (sk SignaturePrivateKey) PublicKey() SignaturePublicKey {
	if len(sk) != SignaturePrivateKeySize {
		return nil
	}
	return SignaturePublicKey(ed25519.PrivateKey(sk).Public().(ed25519.PublicKey))
}

// SignWithLabel implements RFC 9420 section 5.1.6:
//
//	SignWithLabel(SignatureKey, Label, Content) =
//	    Signature.Sign(SignatureKey, SignContent)
//	struct {
//	    opaque label<V> = "MLS 1.0 " + Label;
//	    opaque content<V> = Content;
//	} SignContent;
func SignWithLabel(sk SignaturePrivateKey, label string, content []byte) ([]byte, error) {
	if len(sk) != SignaturePrivateKeySize {
		return nil, fmt.Errorf("crypto: signature key size %d, want %d", len(sk), SignaturePrivateKeySize)
	}
	msg, err := signContent(label, content)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(ed25519.PrivateKey(sk), msg), nil
}

// ErrSignatureInvalid is returned by VerifyWithLabel on signature failure.
var ErrSignatureInvalid = errors.New("crypto: signature verification failed")

// VerifyWithLabel verifies a signature produced by SignWithLabel.
func VerifyWithLabel(pk SignaturePublicKey, label string, content, signature []byte) error {
	if len(pk) != SignaturePublicKeySize {
		return fmt.Errorf("crypto: signature public key size %d, want %d", len(pk), SignaturePublicKeySize)
	}
	if len(signature) != SignatureSize {
		return fmt.Errorf("%w: bad length %d", ErrSignatureInvalid, len(signature))
	}
	msg, err := signContent(label, content)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pk), msg, signature) {
		return ErrSignatureInvalid
	}
	return nil
}

func signContent(label string, content []byte) ([]byte, error) {
	e := mlstls.NewEncoder()
	if err := e.WriteOpaque([]byte(labelPrefix + label)); err != nil {
		return nil, fmt.Errorf("crypto: SignContent label: %w", err)
	}
	if err := e.WriteOpaque(content); err != nil {
		return nil, fmt.Errorf("crypto: SignContent content: %w", err)
	}
	return e.Bytes(), nil
}
