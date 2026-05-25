package mlstls

import (
	"errors"
	"fmt"
)

// MaxVarint is the largest value representable as a QUIC variable-length
// integer (2^62 - 1).
const MaxVarint = (uint64(1) << 62) - 1

// ErrVarintTooLarge is returned when a value exceeds MaxVarint.
var ErrVarintTooLarge = errors.New("mlstls: varint value exceeds 2^62-1")

// ErrNonCanonicalVarint is returned when a decoded varint uses more bytes than
// the minimum required. RFC 9420 inherits the QUIC encoding rules; some MLS
// constructions require canonical encoding so that signed payloads are
// deterministic.
var ErrNonCanonicalVarint = errors.New("mlstls: non-canonical varint encoding")

// VarintSize returns the number of bytes a value occupies when encoded as a
// QUIC varint. It returns 0 if the value is too large to encode.
func VarintSize(v uint64) int {
	switch {
	case v < 1<<6:
		return 1
	case v < 1<<14:
		return 2
	case v < 1<<30:
		return 4
	case v <= MaxVarint:
		return 8
	default:
		return 0
	}
}

// appendVarint appends the QUIC-format encoding of v to buf.
func appendVarint(buf []byte, v uint64) ([]byte, error) {
	switch {
	case v < 1<<6:
		return append(buf, byte(v)), nil
	case v < 1<<14:
		return append(buf, byte(v>>8)|0x40, byte(v)), nil
	case v < 1<<30:
		return append(buf,
			byte(v>>24)|0x80,
			byte(v>>16),
			byte(v>>8),
			byte(v),
		), nil
	case v <= MaxVarint:
		return append(buf,
			byte(v>>56)|0xC0,
			byte(v>>48),
			byte(v>>40),
			byte(v>>32),
			byte(v>>24),
			byte(v>>16),
			byte(v>>8),
			byte(v),
		), nil
	default:
		return buf, ErrVarintTooLarge
	}
}

// readVarint decodes a varint starting at buf[0]. Returns the value, the
// number of bytes consumed, and any error. Enforces canonical (minimum-length)
// encoding because MLS signed payloads require it.
func readVarint(buf []byte) (uint64, int, error) {
	if len(buf) == 0 {
		return 0, 0, fmt.Errorf("mlstls: short varint: empty buffer")
	}
	prefix := buf[0] >> 6
	switch prefix {
	case 0:
		return uint64(buf[0] & 0x3F), 1, nil
	case 1:
		if len(buf) < 2 {
			return 0, 0, fmt.Errorf("mlstls: short varint: need 2 bytes, have %d", len(buf))
		}
		v := uint64(buf[0]&0x3F)<<8 | uint64(buf[1])
		if v < 1<<6 {
			return 0, 0, ErrNonCanonicalVarint
		}
		return v, 2, nil
	case 2:
		if len(buf) < 4 {
			return 0, 0, fmt.Errorf("mlstls: short varint: need 4 bytes, have %d", len(buf))
		}
		v := uint64(buf[0]&0x3F)<<24 |
			uint64(buf[1])<<16 |
			uint64(buf[2])<<8 |
			uint64(buf[3])
		if v < 1<<14 {
			return 0, 0, ErrNonCanonicalVarint
		}
		return v, 4, nil
	default:
		if len(buf) < 8 {
			return 0, 0, fmt.Errorf("mlstls: short varint: need 8 bytes, have %d", len(buf))
		}
		v := uint64(buf[0]&0x3F)<<56 |
			uint64(buf[1])<<48 |
			uint64(buf[2])<<40 |
			uint64(buf[3])<<32 |
			uint64(buf[4])<<24 |
			uint64(buf[5])<<16 |
			uint64(buf[6])<<8 |
			uint64(buf[7])
		if v < 1<<30 {
			return 0, 0, ErrNonCanonicalVarint
		}
		return v, 8, nil
	}
}
