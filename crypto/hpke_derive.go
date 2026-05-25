package crypto

import (
	"crypto/ecdh"
	"fmt"

	"github.com/Deln0r/mls-go/encoding/mlstls"
)

// HPKECiphertext is the wire-level pairing of a KEM output and an AEAD
// ciphertext, used wherever MLS serializes an HPKE-sealed blob (UpdatePath
// path-secret encryptions, EncryptedGroupSecrets, etc.) per RFC 9420
// sections 6.2 and 12.4.
type HPKECiphertext struct {
	KEMOutput  []byte
	Ciphertext []byte
}

// MarshalMLS encodes the ciphertext as two opaque<V> fields.
func (h HPKECiphertext) MarshalMLS(e *mlstls.Encoder) error {
	if err := e.WriteOpaque(h.KEMOutput); err != nil {
		return err
	}
	return e.WriteOpaque(h.Ciphertext)
}

// UnmarshalMLS decodes a ciphertext written by MarshalMLS.
func (h *HPKECiphertext) UnmarshalMLS(d *mlstls.Decoder) error {
	kem, err := d.ReadOpaque()
	if err != nil {
		return err
	}
	ct, err := d.ReadOpaque()
	if err != nil {
		return err
	}
	h.KEMOutput = append([]byte(nil), kem...)
	h.Ciphertext = append([]byte(nil), ct...)
	return nil
}

// DeriveHPKEKey deterministically derives an HPKE keypair from arbitrary
// input keying material per RFC 9180 section 7.1.3 (DeriveKeyPair for
// DHKEM(X25519, HKDF-SHA-256)):
//
//	dkp_prk = LabeledExtract("", "dkp_prk", ikm)
//	sk      = LabeledExpand(dkp_prk, "sk", "", Nsk)
//
// where Nsk = 32 and the labeled helpers use the KEM-suite identifier
// "KEM" || I2OSP(kem_id, 2). The function is used to roll an HPKE node
// keypair out of each path_secret in an UpdatePath.
func DeriveHPKEKey(ikm []byte) (HPKEPrivateKey, HPKEPublicKey, error) {
	if len(ikm) == 0 {
		return nil, nil, fmt.Errorf("crypto: DeriveHPKEKey requires non-empty ikm")
	}
	suite := kemSuiteID()
	dkpPRK := labeledExtract(nil, suite, "dkp_prk", ikm)
	skBytes, err := labeledExpand(dkpPRK, suite, "sk", nil, HPKEPrivateKeySize)
	if err != nil {
		return nil, nil, err
	}
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(skBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: DeriveHPKEKey NewPrivateKey: %w", err)
	}
	return HPKEPrivateKey(priv.Bytes()), HPKEPublicKey(priv.PublicKey().Bytes()), nil
}
