package crypto

// CiphersuiteID enumerates IETF-registered MLS ciphersuites. Only MTI is
// implemented; the rest are listed for completeness so callers can refer to
// them when reporting unsupported configurations.
type CiphersuiteID uint16

const (
	// MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (MTI).
	CiphersuiteMTI CiphersuiteID = 0x0001

	CiphersuiteP256AESCCM     CiphersuiteID = 0x0002
	CiphersuiteX25519Chacha20 CiphersuiteID = 0x0003
	CiphersuiteX448AESGCM     CiphersuiteID = 0x0004
	CiphersuiteP521AESGCM     CiphersuiteID = 0x0005
	CiphersuiteX448Chacha20   CiphersuiteID = 0x0006
	CiphersuiteP384AESGCM     CiphersuiteID = 0x0007
)

// Sizes for the MTI ciphersuite in bytes.
const (
	// HashSize is the SHA-256 output size (Nh in RFC 9420).
	HashSize = 32

	// AEADKeySize is the AES-128-GCM key size (Nk).
	AEADKeySize = 16

	// AEADNonceSize is the AES-GCM nonce size (Nn).
	AEADNonceSize = 12

	// AEADTagSize is the AES-GCM authentication tag size (Nt).
	AEADTagSize = 16

	// HPKEPublicKeySize is the X25519 public key size (Npk).
	HPKEPublicKeySize = 32

	// HPKEPrivateKeySize is the X25519 private key size (Nsk).
	HPKEPrivateKeySize = 32

	// SignaturePublicKeySize is the Ed25519 public key size.
	SignaturePublicKeySize = 32

	// SignaturePrivateKeySize is the Ed25519 expanded private key size used by
	// the standard library (seed plus public key).
	SignaturePrivateKeySize = 64

	// SignatureSize is the Ed25519 signature size.
	SignatureSize = 64
)

// Label prefix applied to every labeled KDF, signature, and MAC operation
// (RFC 9420 sections 5.1.2, 5.1.6, 5.1.3).
const labelPrefix = "MLS 1.0 "

// HPKE numeric ciphersuite identifiers used for the suite_id input to RFC 9180
// labeled extract/expand. See RFC 9180 section 7.1 for the kem_id table and
// section 7.2 / 7.3 for kdf_id / aead_id.
const (
	hpkeKEMID  uint16 = 0x0020 // DHKEM(X25519, HKDF-SHA-256)
	hpkeKDFID  uint16 = 0x0001 // HKDF-SHA-256
	hpkeAEADID uint16 = 0x0001 // AES-128-GCM
)
