// Package tree implements the TreeKEM ratchet tree from RFC 9420 section 7.
//
// The representation is array-based, following the left-balanced binary tree
// layout described in RFC 9420 section 7.1: a tree with n leaves has width
// 2*n - 1, leaves sit at even indices, and parent nodes sit at odd indices.
// All tree math, resolution, and direct-path operations are pure functions on
// NodeIndex values. Tree state (LeafNode / ParentNode contents, blanking) is
// layered on top in tree.go.
package tree
