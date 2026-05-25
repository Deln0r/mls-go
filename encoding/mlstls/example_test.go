package mlstls_test

import (
	"fmt"

	"github.com/Deln0r/mls-go/encoding/mlstls"
)

// keyPackageHeader is a small composite type used as an example of how to
// implement Marshaler and Unmarshaler in concert.
type keyPackageHeader struct {
	Version uint16
	Suite   uint16
	Owner   []byte
}

func (h *keyPackageHeader) MarshalMLS(e *mlstls.Encoder) error {
	e.WriteUint16(h.Version)
	e.WriteUint16(h.Suite)
	return e.WriteOpaque(h.Owner)
}

func (h *keyPackageHeader) UnmarshalMLS(d *mlstls.Decoder) error {
	v, err := d.ReadUint16()
	if err != nil {
		return err
	}
	s, err := d.ReadUint16()
	if err != nil {
		return err
	}
	owner, err := d.ReadOpaque()
	if err != nil {
		return err
	}
	h.Version = v
	h.Suite = s
	h.Owner = append([]byte(nil), owner...)
	return nil
}

// ExampleMarshal_keyPackageHeader shows the simplest end-to-end use of
// the codec: define a struct, implement Marshaler / Unmarshaler, round
// trip through Marshal / Unmarshal.
func ExampleMarshal_keyPackageHeader() {
	in := &keyPackageHeader{Version: 1, Suite: 1, Owner: []byte("alice")}
	wire, err := mlstls.Marshal(in)
	if err != nil {
		panic(err)
	}
	fmt.Printf("wire: %x\n", wire)

	var out keyPackageHeader
	if err := mlstls.Unmarshal(wire, &out); err != nil {
		panic(err)
	}
	fmt.Printf("version=%d suite=%d owner=%s\n", out.Version, out.Suite, out.Owner)

	// Output:
	// wire: 0001000105616c696365
	// version=1 suite=1 owner=alice
}

// ExampleEncoder_WriteVarint demonstrates the QUIC variable-length
// integer encoding required by RFC 9420 section 2.1: values up to 63
// pack into one byte, larger values use two, four, or eight bytes with
// the top two bits of the first byte carrying the length tag.
func ExampleEncoder_WriteVarint() {
	e := mlstls.NewEncoder()
	for _, v := range []uint64{37, 15293, 494878333} {
		if err := e.WriteVarint(v); err != nil {
			panic(err)
		}
	}
	fmt.Printf("%x\n", e.Bytes())
	// Output:
	// 257bbd9d7f3e7d
}
