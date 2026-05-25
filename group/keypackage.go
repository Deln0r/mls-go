package group

import (
	"fmt"

	"github.com/Deln0r/mls-go/crypto"
)

// KeyPackage is the public state advertised by a prospective group member
// so existing groups can Add them. It carries the HPKE init key used to
// receive group secrets, the long-term Ed25519 signature key, and the
// basic-credential identity.
type KeyPackage struct {
	InitKey      crypto.HPKEPublicKey
	SignatureKey crypto.SignaturePublicKey
	Identity     []byte
}

// KeyPackagePrivate pairs a KeyPackage with the private keys held by its
// owner. Returned by GenerateKeyPackage; never shared.
type KeyPackagePrivate struct {
	InitPriv      crypto.HPKEPrivateKey
	SignaturePriv crypto.SignaturePrivateKey
	Public        KeyPackage
}

// GenerateKeyPackage produces a fresh keypair set for a prospective member.
func GenerateKeyPackage(identity string) (*KeyPackagePrivate, error) {
	sigPriv, sigPub, err := crypto.GenerateSignatureKey()
	if err != nil {
		return nil, fmt.Errorf("group: GenerateKeyPackage signature: %w", err)
	}
	initPriv, initPub, err := crypto.GenerateHPKEKey()
	if err != nil {
		return nil, fmt.Errorf("group: GenerateKeyPackage init: %w", err)
	}
	return &KeyPackagePrivate{
		InitPriv:      initPriv,
		SignaturePriv: sigPriv,
		Public: KeyPackage{
			InitKey:      initPub,
			SignatureKey: sigPub,
			Identity:     []byte(identity),
		},
	}, nil
}
