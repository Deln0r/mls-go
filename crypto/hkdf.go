package crypto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/Deln0r/mls-go/encoding/mlstls"
)

// Extract implements HKDF-Extract(salt, ikm) with SHA-256.
func Extract(salt, ikm []byte) []byte {
	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		// hkdf.Extract only fails on internal hash misuse, which cannot happen
		// with SHA-256.
		panic(fmt.Sprintf("crypto: hkdf.Extract unexpected error: %v", err))
	}
	return prk
}

// Expand implements HKDF-Expand(prk, info, length) with SHA-256.
func Expand(prk, info []byte, length int) ([]byte, error) {
	out, err := hkdf.Expand(sha256.New, prk, string(info), length)
	if err != nil {
		return nil, fmt.Errorf("crypto: hkdf.Expand: %w", err)
	}
	return out, nil
}

// ExpandWithLabel implements RFC 9420 section 5.1.2:
//
//	ExpandWithLabel(Secret, Label, Context, Length) =
//	    KDF.Expand(Secret, KDFLabel, Length)
//	struct {
//	    uint16 length = Length;
//	    opaque label<V> = "MLS 1.0 " + Label;
//	    opaque context<V> = Context;
//	} KDFLabel;
func ExpandWithLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	if length < 0 || length > 0xFFFF {
		return nil, fmt.Errorf("crypto: ExpandWithLabel length out of range: %d", length)
	}
	e := mlstls.NewEncoder()
	e.WriteUint16(uint16(length))
	if err := e.WriteOpaque([]byte(labelPrefix + label)); err != nil {
		return nil, fmt.Errorf("crypto: ExpandWithLabel label: %w", err)
	}
	if err := e.WriteOpaque(context); err != nil {
		return nil, fmt.Errorf("crypto: ExpandWithLabel context: %w", err)
	}
	return Expand(secret, e.Bytes(), length)
}

// DeriveSecret implements RFC 9420 section 5.1.2:
//
//	DeriveSecret(Secret, Label) = ExpandWithLabel(Secret, Label, "", KDF.Nh)
func DeriveSecret(secret []byte, label string) ([]byte, error) {
	return ExpandWithLabel(secret, label, nil, HashSize)
}

// DeriveTreeSecret implements RFC 9420 section 7.4:
//
//	DeriveTreeSecret(Secret, Label, Generation, Length) =
//	    ExpandWithLabel(Secret, Label, GenerationOctets, Length)
//
// where GenerationOctets is the uint32 encoded as 4 big-endian bytes.
func DeriveTreeSecret(secret []byte, label string, generation uint32, length int) ([]byte, error) {
	var gen [4]byte
	binary.BigEndian.PutUint32(gen[:], generation)
	return ExpandWithLabel(secret, label, gen[:], length)
}
