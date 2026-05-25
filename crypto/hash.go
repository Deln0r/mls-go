package crypto

import (
	"crypto/sha256"
	"fmt"

	"github.com/Deln0r/mls-go/encoding/mlstls"
)

// Hash returns SHA-256(data).
func Hash(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// RefHash implements RFC 9420 section 5.1.4:
//
//	RefHash(label, value) = Hash(RefHashInput)
//	struct {
//	    opaque label<V>;
//	    opaque value<V>;
//	} RefHashInput;
//
// The label is prefixed with "MLS 1.0 " before encoding.
func RefHash(label string, value []byte) ([]byte, error) {
	e := mlstls.NewEncoder()
	if err := e.WriteOpaque([]byte(labelPrefix + label)); err != nil {
		return nil, fmt.Errorf("crypto: RefHash label: %w", err)
	}
	if err := e.WriteOpaque(value); err != nil {
		return nil, fmt.Errorf("crypto: RefHash value: %w", err)
	}
	return Hash(e.Bytes()), nil
}
