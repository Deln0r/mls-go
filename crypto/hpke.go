package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// HPKEPublicKey is a serialized X25519 public key (32 bytes).
type HPKEPublicKey []byte

// HPKEPrivateKey is a serialized X25519 private key (32 bytes).
type HPKEPrivateKey []byte

// GenerateHPKEKey returns a fresh X25519 keypair for use as an HPKE init key.
func GenerateHPKEKey() (HPKEPrivateKey, HPKEPublicKey, error) {
	curve := ecdh.X25519()
	sk, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: X25519 GenerateKey: %w", err)
	}
	return HPKEPrivateKey(sk.Bytes()), HPKEPublicKey(sk.PublicKey().Bytes()), nil
}

// PublicKey derives the X25519 public key from a private key.
func (sk HPKEPrivateKey) PublicKey() (HPKEPublicKey, error) {
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(sk)
	if err != nil {
		return nil, fmt.Errorf("crypto: X25519 NewPrivateKey: %w", err)
	}
	return HPKEPublicKey(priv.PublicKey().Bytes()), nil
}

// HPKESealBase encrypts pt to pkR in HPKE base mode (RFC 9180 section 6.1).
// info and aad correspond to the MLS spec's per-call parameters. Returns the
// KEM output (enc, serialized ephemeral public key) and the ciphertext.
func HPKESealBase(pkR HPKEPublicKey, info, aad, pt []byte) (enc, ct []byte, err error) {
	shared, enc, err := dhkemEncap(pkR)
	if err != nil {
		return nil, nil, err
	}
	key, nonce, err := keyScheduleBase(shared, info)
	if err != nil {
		return nil, nil, err
	}
	ct, err = AEADSeal(key, nonce, aad, pt)
	if err != nil {
		return nil, nil, err
	}
	return enc, ct, nil
}

// HPKEOpenBase reverses HPKESealBase.
func HPKEOpenBase(skR HPKEPrivateKey, enc, info, aad, ct []byte) ([]byte, error) {
	shared, err := dhkemDecap(enc, skR)
	if err != nil {
		return nil, err
	}
	key, nonce, err := keyScheduleBase(shared, info)
	if err != nil {
		return nil, err
	}
	pt, err := AEADOpen(key, nonce, aad, ct)
	if err != nil {
		return nil, fmt.Errorf("crypto: HPKE OpenBase: %w", err)
	}
	return pt, nil
}

// dhkemEncap implements RFC 9180 section 4.1 Encap for DHKEM(X25519, HKDF-SHA-256).
func dhkemEncap(pkR HPKEPublicKey) (sharedSecret, enc []byte, err error) {
	curve := ecdh.X25519()
	pkRkey, err := curve.NewPublicKey(pkR)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: DHKEM Encap pkR: %w", err)
	}
	skE, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: DHKEM ephemeral keygen: %w", err)
	}
	dh, err := skE.ECDH(pkRkey)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: DHKEM ECDH: %w", err)
	}
	enc = skE.PublicKey().Bytes()
	kemContext := append([]byte{}, enc...)
	kemContext = append(kemContext, pkR...)
	shared, err := extractAndExpand(dh, kemContext)
	if err != nil {
		return nil, nil, err
	}
	return shared, enc, nil
}

// dhkemDecap implements RFC 9180 section 4.1 Decap for DHKEM(X25519, HKDF-SHA-256).
func dhkemDecap(enc []byte, skR HPKEPrivateKey) ([]byte, error) {
	curve := ecdh.X25519()
	skRkey, err := curve.NewPrivateKey(skR)
	if err != nil {
		return nil, fmt.Errorf("crypto: DHKEM Decap skR: %w", err)
	}
	pkE, err := curve.NewPublicKey(enc)
	if err != nil {
		return nil, fmt.Errorf("crypto: DHKEM Decap enc: %w", err)
	}
	dh, err := skRkey.ECDH(pkE)
	if err != nil {
		return nil, fmt.Errorf("crypto: DHKEM ECDH: %w", err)
	}
	pkR := skRkey.PublicKey().Bytes()
	kemContext := append([]byte{}, enc...)
	kemContext = append(kemContext, pkR...)
	return extractAndExpand(dh, kemContext)
}

// extractAndExpand implements RFC 9180 section 4.1:
//
//	eae_prk = LabeledExtract("", "eae_prk", dh)
//	shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)
func extractAndExpand(dh, kemContext []byte) ([]byte, error) {
	eaePRK := labeledExtract(nil, kemSuiteID(), "eae_prk", dh)
	return labeledExpand(eaePRK, kemSuiteID(), "shared_secret", kemContext, HashSize)
}

// keyScheduleBase implements RFC 9180 section 5.1 KeyScheduleS for the base
// mode, producing the AEAD key and base_nonce. Sequence number is zero for
// single-shot sealing in MLS, so base_nonce is used directly.
func keyScheduleBase(sharedSecret, info []byte) (key, nonce []byte, err error) {
	suite := hpkeSuiteID()
	pskIDHash := labeledExtract(nil, suite, "psk_id_hash", nil)
	infoHash := labeledExtract(nil, suite, "info_hash", info)

	ksContext := make([]byte, 0, 1+len(pskIDHash)+len(infoHash))
	ksContext = append(ksContext, 0x00) // mode_base
	ksContext = append(ksContext, pskIDHash...)
	ksContext = append(ksContext, infoHash...)

	secret := labeledExtract(sharedSecret, suite, "secret", nil)

	key, err = labeledExpand(secret, suite, "key", ksContext, AEADKeySize)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = labeledExpand(secret, suite, "base_nonce", ksContext, AEADNonceSize)
	if err != nil {
		return nil, nil, err
	}
	return key, nonce, nil
}

// labeledExtract implements RFC 9180 section 4:
//
//	labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
//	return Extract(salt, labeled_ikm)
func labeledExtract(salt, suiteID []byte, label string, ikm []byte) []byte {
	labeledIKM := make([]byte, 0, 7+len(suiteID)+len(label)+len(ikm))
	labeledIKM = append(labeledIKM, "HPKE-v1"...)
	labeledIKM = append(labeledIKM, suiteID...)
	labeledIKM = append(labeledIKM, label...)
	labeledIKM = append(labeledIKM, ikm...)
	return Extract(salt, labeledIKM)
}

// labeledExpand implements RFC 9180 section 4:
//
//	labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id, label, info)
//	return Expand(prk, labeled_info, L)
func labeledExpand(prk, suiteID []byte, label string, info []byte, length int) ([]byte, error) {
	if length < 0 || length > 0xFFFF {
		return nil, fmt.Errorf("crypto: labeledExpand length out of range: %d", length)
	}
	var lenOctets [2]byte
	binary.BigEndian.PutUint16(lenOctets[:], uint16(length))

	labeledInfo := make([]byte, 0, 2+7+len(suiteID)+len(label)+len(info))
	labeledInfo = append(labeledInfo, lenOctets[:]...)
	labeledInfo = append(labeledInfo, "HPKE-v1"...)
	labeledInfo = append(labeledInfo, suiteID...)
	labeledInfo = append(labeledInfo, label...)
	labeledInfo = append(labeledInfo, info...)
	return Expand(prk, labeledInfo, length)
}

// kemSuiteID is "KEM" || I2OSP(kem_id, 2).
func kemSuiteID() []byte {
	out := make([]byte, 0, 5)
	out = append(out, "KEM"...)
	out = binary.BigEndian.AppendUint16(out, hpkeKEMID)
	return out
}

// hpkeSuiteID is "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2).
func hpkeSuiteID() []byte {
	out := make([]byte, 0, 10)
	out = append(out, "HPKE"...)
	out = binary.BigEndian.AppendUint16(out, hpkeKEMID)
	out = binary.BigEndian.AppendUint16(out, hpkeKDFID)
	out = binary.BigEndian.AppendUint16(out, hpkeAEADID)
	return out
}

// ErrHPKEOpen is returned by HPKEOpenBase when authentication fails.
var ErrHPKEOpen = errors.New("crypto: HPKE OpenBase failed")
