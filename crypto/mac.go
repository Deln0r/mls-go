package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

// MAC computes HMAC-SHA-256(key, data). RFC 9420 uses this construction
// directly (no MLS label prefix) for confirmation_tag and the membership_tag
// of an authenticated FramedContent.
func MAC(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// MACEqual returns true if a and b are equal in constant time.
func MACEqual(a, b []byte) bool {
	return hmac.Equal(a, b)
}
