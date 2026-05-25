package group

import (
	"fmt"

	"github.com/Deln0r/mls-go/crypto"
)

// EpochKeys holds the derived secrets that exist within an epoch.
// epoch_secret is the root from which the others are derived; the rest are
// the keys consumed by other parts of RFC 9420 (init for the next epoch,
// confirmation for transcript verification, membership for FramedContent
// authentication, authentication for exporters).
type EpochKeys struct {
	EpochSecret        []byte
	InitSecret         []byte
	ConfirmationKey    []byte
	MembershipKey      []byte
	EpochAuthenticator []byte
}

// deriveEpoch implements the RFC 9420 section 8.1 key schedule:
//
//	joiner_secret = ExpandWithLabel(
//	    KDF.Extract(prev_init_secret, commit_secret),
//	    "joiner", GroupContext, KDF.Nh)
//	member_secret = KDF.Extract(joiner_secret, psk_secret)
//	epoch_secret  = ExpandWithLabel(member_secret, "epoch",
//	                                GroupContext, KDF.Nh)
//	init_secret           = DeriveSecret(epoch_secret, "init")
//	confirmation_key      = DeriveSecret(epoch_secret, "confirm")
//	membership_key        = DeriveSecret(epoch_secret, "membership")
//	epoch_authenticator   = DeriveSecret(epoch_secret, "authentication")
//
// psk_secret is the all-zero KDF.Nh string when no PSK is in effect.
//
// Returns the derived EpochKeys plus the joiner_secret. The joiner_secret
// is shipped (sealed via HPKE) to new joiners in the Welcome message so
// they can derive the same epoch_secret without knowing prev_init_secret.
func deriveEpoch(prevInitSecret, commitSecret []byte, gc GroupContext) (*EpochKeys, []byte, error) {
	gcBytes, err := gc.Marshal()
	if err != nil {
		return nil, nil, fmt.Errorf("group: deriveEpoch marshal context: %w", err)
	}

	earlySecret := crypto.Extract(prevInitSecret, commitSecret)
	joinerSecret, err := crypto.ExpandWithLabel(earlySecret, "joiner", gcBytes, crypto.HashSize)
	if err != nil {
		return nil, nil, fmt.Errorf("group: deriveEpoch joiner: %w", err)
	}

	pskSecret := make([]byte, crypto.HashSize)
	memberSecret := crypto.Extract(joinerSecret, pskSecret)

	epochSecret, err := crypto.ExpandWithLabel(memberSecret, "epoch", gcBytes, crypto.HashSize)
	if err != nil {
		return nil, nil, fmt.Errorf("group: deriveEpoch epoch: %w", err)
	}

	initSecret, err := crypto.DeriveSecret(epochSecret, "init")
	if err != nil {
		return nil, nil, err
	}
	confirmationKey, err := crypto.DeriveSecret(epochSecret, "confirm")
	if err != nil {
		return nil, nil, err
	}
	membershipKey, err := crypto.DeriveSecret(epochSecret, "membership")
	if err != nil {
		return nil, nil, err
	}
	epochAuth, err := crypto.DeriveSecret(epochSecret, "authentication")
	if err != nil {
		return nil, nil, err
	}

	return &EpochKeys{
		EpochSecret:        epochSecret,
		InitSecret:         initSecret,
		ConfirmationKey:    confirmationKey,
		MembershipKey:      membershipKey,
		EpochAuthenticator: epochAuth,
	}, joinerSecret, nil
}

// deriveEpochFromJoiner is the joiner's side of deriveEpoch: it skips the
// first Extract because joiner_secret already arrived via Welcome.
func deriveEpochFromJoiner(joinerSecret []byte, gc GroupContext) (*EpochKeys, error) {
	gcBytes, err := gc.Marshal()
	if err != nil {
		return nil, fmt.Errorf("group: deriveEpochFromJoiner marshal context: %w", err)
	}

	pskSecret := make([]byte, crypto.HashSize)
	memberSecret := crypto.Extract(joinerSecret, pskSecret)

	epochSecret, err := crypto.ExpandWithLabel(memberSecret, "epoch", gcBytes, crypto.HashSize)
	if err != nil {
		return nil, fmt.Errorf("group: deriveEpochFromJoiner epoch: %w", err)
	}

	initSecret, err := crypto.DeriveSecret(epochSecret, "init")
	if err != nil {
		return nil, err
	}
	confirmationKey, err := crypto.DeriveSecret(epochSecret, "confirm")
	if err != nil {
		return nil, err
	}
	membershipKey, err := crypto.DeriveSecret(epochSecret, "membership")
	if err != nil {
		return nil, err
	}
	epochAuth, err := crypto.DeriveSecret(epochSecret, "authentication")
	if err != nil {
		return nil, err
	}

	return &EpochKeys{
		EpochSecret:        epochSecret,
		InitSecret:         initSecret,
		ConfirmationKey:    confirmationKey,
		MembershipKey:      membershipKey,
		EpochAuthenticator: epochAuth,
	}, nil
}
