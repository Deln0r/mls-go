package mlstls

import (
	"bytes"
	"errors"
	"testing"
)

// Canonical QUIC varint test vectors from RFC 9000, appendix A.1. The same
// section notes that 37 may also be encoded as 0x4025, 0x80000025, or
// 0xC000000000000025; those non-canonical alternatives are exercised in
// TestVarintNonCanonicalRejected.
var rfc9000VarintVectors = []struct {
	hex   string
	value uint64
}{
	{"00", 0},
	{"25", 37},
	{"7bbd", 15293},
	{"9d7f3e7d", 494878333},
	{"c2197c5eff14e88c", 151288809941952652},
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	if len(s)%2 != 0 {
		t.Fatalf("odd hex length: %q", s)
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi, ok1 := hexNibble(s[i])
		lo, ok2 := hexNibble(s[i+1])
		if !ok1 || !ok2 {
			t.Fatalf("bad hex char in %q", s)
		}
		out[i/2] = hi<<4 | lo
	}
	return out
}

func hexNibble(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return 10 + b - 'a', true
	case b >= 'A' && b <= 'F':
		return 10 + b - 'A', true
	}
	return 0, false
}

func TestVarintRoundtripCanonical(t *testing.T) {
	for _, tc := range rfc9000VarintVectors {
		t.Run(tc.hex, func(t *testing.T) {
			want := mustHex(t, tc.hex)

			e := NewEncoder()
			if err := e.WriteVarint(tc.value); err != nil {
				t.Fatalf("WriteVarint(%d) error: %v", tc.value, err)
			}
			if !bytes.Equal(e.Bytes(), want) {
				t.Fatalf("encode mismatch:\n got  %x\n want %x", e.Bytes(), want)
			}

			d := NewDecoder(want)
			got, err := d.ReadVarint()
			if err != nil {
				t.Fatalf("ReadVarint error: %v", err)
			}
			if got != tc.value {
				t.Fatalf("decode mismatch: got %d, want %d", got, tc.value)
			}
			if !d.Empty() {
				t.Fatalf("decoder not empty: %d bytes left", d.Remaining())
			}
		})
	}
}

func TestVarintNonCanonicalRejected(t *testing.T) {
	// Each of these encodes a value with more bytes than necessary. The
	// 4025 / 80000025 / C000000000000025 cases come straight from RFC 9000,
	// appendix A.1, where they appear as non-canonical alternatives for 37.
	cases := [][]byte{
		{0x40, 0x00},             // 2-byte 0
		{0x80, 0x00, 0x00, 0x00}, // 4-byte 0
		{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 8-byte 0
		{0x40, 0x25},             // 2-byte 37
		{0x80, 0x00, 0x00, 0x25}, // 4-byte 37
		{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25}, // 8-byte 37
		{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00}, // 8-byte 4096
	}
	for i, c := range cases {
		d := NewDecoder(c)
		_, err := d.ReadVarint()
		if !errors.Is(err, ErrNonCanonicalVarint) {
			t.Errorf("case %d: want ErrNonCanonicalVarint, got %v", i, err)
		}
	}
}

func TestVarintBoundaries(t *testing.T) {
	boundaries := []uint64{
		0,
		(1 << 6) - 1,
		1 << 6,
		(1 << 14) - 1,
		1 << 14,
		(1 << 30) - 1,
		1 << 30,
		MaxVarint,
	}
	for _, v := range boundaries {
		e := NewEncoder()
		if err := e.WriteVarint(v); err != nil {
			t.Fatalf("WriteVarint(%d): %v", v, err)
		}
		if VarintSize(v) != len(e.Bytes()) {
			t.Errorf("VarintSize(%d) = %d, encoded %d bytes", v, VarintSize(v), len(e.Bytes()))
		}
		d := NewDecoder(e.Bytes())
		got, err := d.ReadVarint()
		if err != nil {
			t.Fatalf("ReadVarint(%d encoded): %v", v, err)
		}
		if got != v {
			t.Fatalf("roundtrip mismatch: %d -> %d", v, got)
		}
	}
}

func TestVarintTooLarge(t *testing.T) {
	e := NewEncoder()
	if err := e.WriteVarint(MaxVarint + 1); !errors.Is(err, ErrVarintTooLarge) {
		t.Fatalf("want ErrVarintTooLarge, got %v", err)
	}
}

func TestFixedWidthIntsRoundtrip(t *testing.T) {
	e := NewEncoder()
	e.WriteUint8(0x12)
	e.WriteUint16(0x3456)
	e.WriteUint32(0x789ABCDE)
	e.WriteUint64(0xF0E1D2C3B4A59687)

	want := []byte{
		0x12,
		0x34, 0x56,
		0x78, 0x9A, 0xBC, 0xDE,
		0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,
	}
	if !bytes.Equal(e.Bytes(), want) {
		t.Fatalf("encode mismatch:\n got  %x\n want %x", e.Bytes(), want)
	}

	d := NewDecoder(want)
	u8, _ := d.ReadUint8()
	u16, _ := d.ReadUint16()
	u32, _ := d.ReadUint32()
	u64, _ := d.ReadUint64()
	if u8 != 0x12 || u16 != 0x3456 || u32 != 0x789ABCDE || u64 != 0xF0E1D2C3B4A59687 {
		t.Fatalf("readback mismatch: %x %x %x %x", u8, u16, u32, u64)
	}
	if !d.Empty() {
		t.Fatalf("decoder not empty")
	}
}

func TestOpaqueRoundtrip(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x01},
		bytes.Repeat([]byte{0xAB}, 63),  // last 1-byte length
		bytes.Repeat([]byte{0xCD}, 64),  // first 2-byte length
		bytes.Repeat([]byte{0xEF}, 300), // 2-byte length
	}
	for i, c := range cases {
		e := NewEncoder()
		if err := e.WriteOpaque(c); err != nil {
			t.Fatalf("case %d WriteOpaque: %v", i, err)
		}
		d := NewDecoder(e.Bytes())
		got, err := d.ReadOpaque()
		if err != nil {
			t.Fatalf("case %d ReadOpaque: %v", i, err)
		}
		if !bytes.Equal(got, c) {
			t.Fatalf("case %d: got %x, want %x", i, got, c)
		}
		if !d.Empty() {
			t.Fatalf("case %d: %d trailing bytes", i, d.Remaining())
		}
	}
}

type triple struct {
	A uint16
	B []byte
	C uint32
}

func (t *triple) MarshalMLS(e *Encoder) error {
	e.WriteUint16(t.A)
	if err := e.WriteOpaque(t.B); err != nil {
		return err
	}
	e.WriteUint32(t.C)
	return nil
}

func (t *triple) UnmarshalMLS(d *Decoder) error {
	a, err := d.ReadUint16()
	if err != nil {
		return err
	}
	b, err := d.ReadOpaque()
	if err != nil {
		return err
	}
	c, err := d.ReadUint32()
	if err != nil {
		return err
	}
	t.A, t.B, t.C = a, append([]byte(nil), b...), c
	return nil
}

func TestVectorOfMarshalers(t *testing.T) {
	in := []triple{
		{A: 1, B: []byte("alice"), C: 100},
		{A: 2, B: []byte("bob"), C: 200},
		{A: 3, B: nil, C: 300},
	}

	e := NewEncoder()
	err := e.WriteVector(func(sub *Encoder) error {
		for i := range in {
			if err := in[i].MarshalMLS(sub); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WriteVector: %v", err)
	}

	var out []triple
	d := NewDecoder(e.Bytes())
	err = d.ReadVector(func(sub *Decoder) error {
		for !sub.Empty() {
			var t triple
			if err := t.UnmarshalMLS(sub); err != nil {
				return err
			}
			out = append(out, t)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("ReadVector: %v", err)
	}
	if !d.Empty() {
		t.Fatalf("outer decoder has %d trailing bytes", d.Remaining())
	}

	if len(out) != len(in) {
		t.Fatalf("length mismatch: in %d, out %d", len(in), len(out))
	}
	for i := range in {
		if in[i].A != out[i].A || in[i].C != out[i].C || !bytes.Equal(in[i].B, out[i].B) {
			t.Errorf("element %d mismatch: in %+v out %+v", i, in[i], out[i])
		}
	}
}

func TestReadVectorTrailingBytes(t *testing.T) {
	// Vector framing claims 4 bytes, but inner reads only 2.
	buf := []byte{0x04, 0x01, 0x02, 0x03, 0x04}
	d := NewDecoder(buf)
	err := d.ReadVector(func(sub *Decoder) error {
		_, err := sub.ReadUint16()
		return err
	})
	if !errors.Is(err, ErrTrailingBytes) {
		t.Fatalf("want ErrTrailingBytes, got %v", err)
	}
}

func TestUnmarshalTrailingBytes(t *testing.T) {
	in := &triple{A: 7, B: []byte("x"), C: 9}
	wire, err := Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	wire = append(wire, 0xFF)

	var out triple
	if err := Unmarshal(wire, &out); !errors.Is(err, ErrTrailingBytes) {
		t.Fatalf("want ErrTrailingBytes, got %v", err)
	}
}

func TestShortBuffer(t *testing.T) {
	d := NewDecoder([]byte{0x01})
	if _, err := d.ReadUint32(); !errors.Is(err, ErrShortBuffer) {
		t.Fatalf("want ErrShortBuffer, got %v", err)
	}
}
