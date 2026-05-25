package mlstls

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Marshaler is implemented by types that can serialize themselves into MLS
// wire format. Implementations should not assume the encoder is empty.
type Marshaler interface {
	MarshalMLS(e *Encoder) error
}

// Encoder accumulates MLS wire bytes. The zero value is ready to use.
type Encoder struct {
	buf []byte
}

// NewEncoder returns a fresh Encoder. Equivalent to &Encoder{} but reads
// nicer at the call site.
func NewEncoder() *Encoder {
	return &Encoder{}
}

// Bytes returns the accumulated output. The returned slice aliases the
// Encoder's internal buffer; copy it if the Encoder will be reused.
func (e *Encoder) Bytes() []byte {
	return e.buf
}

// Len returns the number of bytes accumulated so far.
func (e *Encoder) Len() int {
	return len(e.buf)
}

// WriteUint8 writes a single byte.
func (e *Encoder) WriteUint8(v uint8) {
	e.buf = append(e.buf, v)
}

// WriteUint16 writes a big-endian uint16.
func (e *Encoder) WriteUint16(v uint16) {
	e.buf = binary.BigEndian.AppendUint16(e.buf, v)
}

// WriteUint32 writes a big-endian uint32.
func (e *Encoder) WriteUint32(v uint32) {
	e.buf = binary.BigEndian.AppendUint32(e.buf, v)
}

// WriteUint64 writes a big-endian uint64.
func (e *Encoder) WriteUint64(v uint64) {
	e.buf = binary.BigEndian.AppendUint64(e.buf, v)
}

// WriteVarint writes a QUIC variable-length integer (RFC 9000, section 16).
// Values larger than 2^62-1 produce ErrVarintTooLarge.
func (e *Encoder) WriteVarint(v uint64) error {
	out, err := appendVarint(e.buf, v)
	if err != nil {
		return err
	}
	e.buf = out
	return nil
}

// WriteRaw appends b to the output verbatim, with no length prefix. Use for
// fixed-length opaque fields (e.g. fixed-size hashes or public keys whose
// length is implied by the ciphersuite).
func (e *Encoder) WriteRaw(b []byte) {
	e.buf = append(e.buf, b...)
}

// WriteOpaque writes a variable-length opaque value: a varint length prefix
// followed by the data.
func (e *Encoder) WriteOpaque(b []byte) error {
	if err := e.WriteVarint(uint64(len(b))); err != nil {
		return err
	}
	e.buf = append(e.buf, b...)
	return nil
}

// WriteVector frames a variable-length sequence: it invokes inner against a
// fresh sub-encoder, then writes the sub-encoder's byte length as a varint
// followed by the sub-encoder's bytes. This is the canonical pattern for
// every "vector<...>" type in the MLS spec.
func (e *Encoder) WriteVector(inner func(*Encoder) error) error {
	sub := &Encoder{}
	if err := inner(sub); err != nil {
		return err
	}
	if err := e.WriteVarint(uint64(len(sub.buf))); err != nil {
		return err
	}
	e.buf = append(e.buf, sub.buf...)
	return nil
}

// WriteMarshaler is a convenience for m.MarshalMLS(e).
func (e *Encoder) WriteMarshaler(m Marshaler) error {
	if m == nil {
		return errors.New("mlstls: WriteMarshaler called with nil")
	}
	return m.MarshalMLS(e)
}

// Marshal encodes m to a fresh byte slice.
func Marshal(m Marshaler) ([]byte, error) {
	e := &Encoder{}
	if err := m.MarshalMLS(e); err != nil {
		return nil, fmt.Errorf("mlstls: marshal: %w", err)
	}
	return e.buf, nil
}
