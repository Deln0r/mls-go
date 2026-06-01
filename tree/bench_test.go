package tree

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/Deln0r/mls-go/crypto"
)

// buildTree returns a populated tree with n leaves whose contents are
// deterministically derived from the leaf index. n must be a positive
// power of two so the tree is a clean left-balanced shape.
func buildTree(b *testing.B, n int) *Tree {
	b.Helper()
	if n < 1 {
		b.Fatalf("buildTree: need at least 1 leaf, got %d", n)
	}
	tr := New(syntheticLeaf(0))
	for i := 1; i < n; i++ {
		if _, err := tr.AddLeaf(syntheticLeaf(uint32(i))); err != nil {
			b.Fatalf("AddLeaf %d: %v", i, err)
		}
	}
	// Populate every parent on every leaf's direct path with a non-blank
	// ParentNode so Resolution and Hash exercise the populated-parent path
	// rather than the blank-fallback path.
	for li := uint32(0); li < uint32(n); li++ {
		for _, idx := range LeafIndex(li).ToNode().DirectPath(tr.Width()) {
			if tr.Parent(idx) == nil {
				_ = tr.SetParent(idx, &ParentNode{
					EncryptionKey: bytes.Repeat([]byte{byte(idx)}, crypto.HPKEPublicKeySize),
				})
			}
		}
	}
	return tr
}

func syntheticLeaf(i uint32) *LeafNode {
	return &LeafNode{
		EncryptionKey: bytes.Repeat([]byte{byte(i)}, crypto.HPKEPublicKeySize),
		SignatureKey:  bytes.Repeat([]byte{byte(i ^ 0x55)}, crypto.SignaturePublicKeySize),
		Credential:    BasicCredential([]byte(fmt.Sprintf("user-%d", i))),
		Source:        LeafNodeSourceKeyPackage,
	}
}

// BenchmarkHash measures the recursive RFC 9420 section 7.8 tree_hash over
// fully populated trees of varying size. Hashing scales O(n) with leaf
// count because every node hashes a constant number of bytes (the
// optional<LeafNode/ParentNode> plus two child hashes).
func BenchmarkHash(b *testing.B) {
	for _, n := range []int{4, 8, 16, 64} {
		tr := buildTree(b, n)
		b.Run(fmt.Sprintf("leaves=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := Hash(tr); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkResolution measures resolution at the root for trees with
// varying populated-parent density. With every parent populated,
// Resolution returns [root] plus the unmerged_leaves list; with all
// parents blanked, it falls through to a left-to-right walk of populated
// leaves.
func BenchmarkResolution(b *testing.B) {
	for _, n := range []int{4, 8, 16, 64} {
		populated := buildTree(b, n)
		blanked := buildTree(b, n)
		// Blank every parent on the blanked variant so Resolution walks the
		// children instead of returning the single populated root.
		for i := uint32(1); i < blanked.Width(); i += 2 {
			_ = blanked.BlankParent(NodeIndex(i))
		}

		b.Run(fmt.Sprintf("leaves=%d/populated_parents", n), func(b *testing.B) {
			root := Root(populated.Width())
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = populated.Resolution(root)
			}
		})

		b.Run(fmt.Sprintf("leaves=%d/blank_parents", n), func(b *testing.B) {
			root := Root(blanked.Width())
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = blanked.Resolution(root)
			}
		})
	}
}

// BenchmarkDirectPath measures the pure node-math path from a leaf to the
// root. No tree state is touched; results are O(log n).
func BenchmarkDirectPath(b *testing.B) {
	for _, n := range []int{4, 8, 16, 64, 256, 1024} {
		width := NodeWidth(uint32(n))
		leaf := LeafIndex(0).ToNode()
		b.Run(fmt.Sprintf("leaves=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = leaf.DirectPath(width)
			}
		})
	}
}

// BenchmarkAddLeaf measures the cost of growing a tree from 1 leaf to n
// leaves, which is the protocol-relevant cost for processing a Commit
// that admits multiple new members at once.
func BenchmarkAddLeaf(b *testing.B) {
	for _, n := range []int{8, 32, 128} {
		b.Run(fmt.Sprintf("leaves=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				tr := New(syntheticLeaf(0))
				for j := 1; j < n; j++ {
					if _, err := tr.AddLeaf(syntheticLeaf(uint32(j))); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
