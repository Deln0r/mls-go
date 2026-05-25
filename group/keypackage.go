package group

import (
	"errors"
	"fmt"

	"github.com/Deln0r/mls-go/crypto"
	"github.com/Deln0r/mls-go/encoding/mlstls"
)

// KeyPackage is the public state advertised by a prospective group member
// so existing groups can Add them. It carries the HPKE init key used to
// receive group secrets, the long-term Ed25519 signature key, the
// basic-credential identity, and a signature over the previous fields
// using the SignatureKey under the "KeyPackageTBS" label per RFC 9420
// section 5.1.6.
type KeyPackage struct {
	InitKey      crypto.HPKEPublicKey
	SignatureKey crypto.SignaturePublicKey
	Identity     []byte
	Signature    []byte
}

// KeyPackagePrivate pairs a KeyPackage with the private keys held by its
// owner. Returned by GenerateKeyPackage; never shared.
type KeyPackagePrivate struct {
	InitPriv      crypto.HPKEPrivateKey
	SignaturePriv crypto.SignaturePrivateKey
	Public        KeyPackage
}

// keyPackageTBS encodes the canonical to-be-signed form of a KeyPackage:
// the opaque-framed init_key, signature_key, and identity. Future
// extensions append after identity preserving prefix stability.
func (kp KeyPackage) keyPackageTBS() ([]byte, error) {
	e := mlstls.NewEncoder()
	if err := e.WriteOpaque(kp.InitKey); err != nil {
		return nil, err
	}
	if err := e.WriteOpaque(kp.SignatureKey); err != nil {
		return nil, err
	}
	if err := e.WriteOpaque(kp.Identity); err != nil {
		return nil, err
	}
	return e.Bytes(), nil
}

// ErrKeyPackageSignature is returned when a KeyPackage signature does not
// verify against its own SignatureKey.
var ErrKeyPackageSignature = errors.New("group: KeyPackage signature invalid")

// Verify checks that the signature was produced by SignatureKey over the
// canonical TBS bytes using the "KeyPackageTBS" label.
func (kp KeyPackage) Verify() error {
	tbs, err := kp.keyPackageTBS()
	if err != nil {
		return err
	}
	if err := crypto.VerifyWithLabel(kp.SignatureKey, "KeyPackageTBS", tbs, kp.Signature); err != nil {
		return fmt.Errorf("%w: %s", ErrKeyPackageSignature, err)
	}
	return nil
}

// GenerateKeyPackage produces a fresh keypair set for a prospective member
// and signs the resulting KeyPackage under the "KeyPackageTBS" label.
func GenerateKeyPackage(identity string) (*KeyPackagePrivate, error) {
	sigPriv, sigPub, err := crypto.GenerateSignatureKey()
	if err != nil {
		return nil, fmt.Errorf("group: GenerateKeyPackage signature: %w", err)
	}
	initPriv, initPub, err := crypto.GenerateHPKEKey()
	if err != nil {
		return nil, fmt.Errorf("group: GenerateKeyPackage init: %w", err)
	}
	kp := KeyPackage{
		InitKey:      initPub,
		SignatureKey: sigPub,
		Identity:     []byte(identity),
	}
	tbs, err := kp.keyPackageTBS()
	if err != nil {
		return nil, err
	}
	sig, err := crypto.SignWithLabel(sigPriv, "KeyPackageTBS", tbs)
	if err != nil {
		return nil, fmt.Errorf("group: GenerateKeyPackage sign: %w", err)
	}
	kp.Signature = sig
	return &KeyPackagePrivate{
		InitPriv:      initPriv,
		SignaturePriv: sigPriv,
		Public:        kp,
	}, nil
}
