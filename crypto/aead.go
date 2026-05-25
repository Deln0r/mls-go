package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

// AEADSeal encrypts plaintext with AES-128-GCM. key must be AEADKeySize bytes,
// nonce must be AEADNonceSize bytes.
func AEADSeal(key, nonce, aad, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != AEADNonceSize {
		return nil, fmt.Errorf("crypto: AEAD nonce size %d, want %d", len(nonce), AEADNonceSize)
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

// AEADOpen decrypts ciphertext sealed with AEADSeal.
func AEADOpen(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != AEADNonceSize {
		return nil, fmt.Errorf("crypto: AEAD nonce size %d, want %d", len(nonce), AEADNonceSize)
	}
	pt, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("crypto: AEAD open: %w", err)
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != AEADKeySize {
		return nil, fmt.Errorf("crypto: AEAD key size %d, want %d", len(key), AEADKeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: cipher.NewGCM: %w", err)
	}
	return gcm, nil
}

// ErrAEADOpen is the sentinel returned when AEAD authentication fails.
var ErrAEADOpen = errors.New("crypto: AEAD authentication failed")
