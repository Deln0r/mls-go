// Package mls is a pure-Go implementation of RFC 9420 Messaging Layer
// Security.
//
// The repository root is intentionally empty of types: callers depend on the
// concrete subpackages directly.
//
//	github.com/Deln0r/mls-go/crypto    Ciphersuite primitives.
//	github.com/Deln0r/mls-go/encoding  TLS presentation language codec.
//	github.com/Deln0r/mls-go/tree      Array-based ratchet tree.
//	github.com/Deln0r/mls-go/group     Group lifecycle, key schedule, Welcome.
package mls
