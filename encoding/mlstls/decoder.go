package mlstls

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Unmarshaler is implemented by types that can deserialize themselves from
// MLS wire format. Implementations should consume exactly their own bytes
// from the decoder.
type Unmarshaler interface {
	UnmarshalMLS(d *Decoder) error
}

// ErrShortBuffer is returned when a read requires more bytes than remain.
var ErrShortBuffer = errors.New("mlstls: short buffer")

// ErrTrailingBytes is returned by Unmarshal when bytes remain after a
// top-level decode completes.
var ErrTrailingBytes = errors.New("mlstls: trailing bytes after decode")

// Decoder consumes MLS wire bytes from a backing slice.
type Decoder struct {
	buf []byte
	pos int
}

// NewDecoder wraps b. The decoder does not copy b; callers must not mutate it
// while the decoder is in use.
func NewDecoder(b []byte) *Decoder {
	return &Decoder{buf: b}
}

// Remaining returns the number of bytes left to consume.
func (d *Decoder) Remaining() int {
	return len(d.buf) - d.pos
}

// Empty reports whether the decoder has consumed all input.
func (d *Decoder) Empty() bool {
	return d.pos >= len(d.buf)
}

func (d *Decoder) take(n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("mlstls: negative read length %d", n)
	}
	if d.Remaining() < n {
		return nil, fmt.Errorf("%w: want %d, have %d", ErrShortBuffer, n, d.Remaining())
	}
	out := d.buf[d.pos : d.pos+n]
	d.pos += n
	return out, nil
}

// ReadUint8 consumes one byte.
func (d *Decoder) ReadUint8() (uint8, error) {
	b, err := d.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

// ReadUint16 consumes a big-endian uint16.
func (d *Decoder) ReadUint16() (uint16, error) {
	b, err := d.take(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

// ReadUint32 consumes a big-endian uint32.
func (d *Decoder) ReadUint32() (uint32, error) {
	b, err := d.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

// ReadUint64 consumes a big-endian uint64.
func (d *Decoder) ReadUint64() (uint64, error) {
	b, err := d.take(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}

// ReadVarint consumes a QUIC varint. Non-canonical encodings are rejected.
func (d *Decoder) ReadVarint() (uint64, error) {
	v, n, err := readVarint(d.buf[d.pos:])
	if err != nil {
		return 0, err
	}
	d.pos += n
	return v, nil
}

// ReadRaw consumes exactly n bytes. The returned slice aliases the decoder's
// buffer; copy it if you need to retain the bytes past further reads.
func (d *Decoder) ReadRaw(n int) ([]byte, error) {
	b, err := d.take(n)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// ReadOpaque consumes a varint length followed by that many bytes. The
// returned slice aliases the decoder's buffer.
func (d *Decoder) ReadOpaque() ([]byte, error) {
	length, err := d.ReadVarint()
	if err != nil {
		return nil, err
	}
	if length > uint64(d.Remaining()) {
		return nil, fmt.Errorf("%w: opaque length %d, remaining %d", ErrShortBuffer, length, d.Remaining())
	}
	return d.take(int(length))
}

// ReadVector consumes a varint byte-length prefix and invokes inner against a
// sub-decoder covering exactly those bytes. Inner is required to consume the
// entire sub-decoder; remaining bytes raise ErrTrailingBytes.
func (d *Decoder) ReadVector(inner func(*Decoder) error) error {
	length, err := d.ReadVarint()
	if err != nil {
		return err
	}
	if length > uint64(d.Remaining()) {
		return fmt.Errorf("%w: vector length %d, remaining %d", ErrShortBuffer, length, d.Remaining())
	}
	region, err := d.take(int(length))
	if err != nil {
		return err
	}
	sub := &Decoder{buf: region}
	if err := inner(sub); err != nil {
		return err
	}
	if !sub.Empty() {
		return fmt.Errorf("%w: %d bytes left inside vector", ErrTrailingBytes, sub.Remaining())
	}
	return nil
}

// ReadMarshaler is a convenience for u.UnmarshalMLS(d).
func (d *Decoder) ReadMarshaler(u Unmarshaler) error {
	if u == nil {
		return errors.New("mlstls: ReadMarshaler called with nil")
	}
	return u.UnmarshalMLS(d)
}

// Unmarshal decodes b into u and verifies that no bytes remain.
func Unmarshal(b []byte, u Unmarshaler) error {
	d := NewDecoder(b)
	if err := u.UnmarshalMLS(d); err != nil {
		return fmt.Errorf("mlstls: unmarshal: %w", err)
	}
	if !d.Empty() {
		return fmt.Errorf("%w: %d bytes left", ErrTrailingBytes, d.Remaining())
	}
	return nil
}
