// Package mlstls implements the wire encoding used by RFC 9420 Messaging
// Layer Security: the TLS presentation language (RFC 8446, section 3) with
// variable-length vector lengths encoded as QUIC variable-length integers
// (RFC 9000, section 16), as specified in RFC 9420, section 2.1.
//
// The API is two concrete types: Encoder accumulates output, Decoder consumes
// input. Variable-length sequences are written and read with WriteVector /
// ReadVector, which frame an inner callback with a varint byte-length prefix.
// Marshaler and Unmarshaler let higher-level MLS types compose cleanly.
package mlstls
