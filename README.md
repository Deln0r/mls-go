# mls-go

A pure-Go implementation of [RFC 9420 Messaging Layer Security (MLS)](https://datatracker.ietf.org/doc/rfc9420/).

[![CI](https://github.com/Deln0r/mls-go/actions/workflows/ci.yml/badge.svg)](https://github.com/Deln0r/mls-go/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Deln0r/mls-go.svg)](https://pkg.go.dev/github.com/Deln0r/mls-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/Deln0r/mls-go)](https://goreportcard.com/report/github.com/Deln0r/mls-go)
[![Go](https://img.shields.io/badge/go-1.26+-blue)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> MLS is the IETF group-messaging end-to-end encryption protocol. `mls-go` ports the cryptographic core, the TLS-presentation wire codec, the array-based ratchet tree with TreeKEM, and the section-8.1 key schedule to idiomatic Go with zero cgo.

## What is implemented

| Component | RFC 9420 | Source |
| --- | --- | --- |
| TLS presentation language codec, QUIC varint length prefixes | § 2.1 | [`encoding/mlstls/`](encoding/mlstls/) |
| MTI ciphersuite primitives: SHA-256, HKDF, AES-128-GCM, Ed25519, HPKE base / DHKEM(X25519, HKDF-SHA-256) | § 5 | [`crypto/`](crypto/) |
| `ExpandWithLabel`, `DeriveSecret`, `DeriveTreeSecret`, `RefHash`, `SignWithLabel`, `VerifyWithLabel`, `MAC` | § 5.1 | [`crypto/`](crypto/) |
| Array-based left-balanced ratchet tree, full node math (level, parent, sibling, direct path, copath, resolution, common ancestor) | § 7.1 | [`tree/math.go`](tree/math.go) |
| `LeafNode` and `ParentNode` wire formats, all three `LeafNodeSource` variants, `Credential`, `Capabilities`, `Lifetime`, `Extension` | § 7.2, § 7.6 | [`tree/leaf_node.go`](tree/leaf_node.go), [`tree/parent_node.go`](tree/parent_node.go) |
| Recursive `tree_hash` via `TreeHashInput` / `LeafNodeHashInput` / `ParentNodeHashInput` | § 7.8 | [`tree/tree_hash.go`](tree/tree_hash.go) |
| `UpdatePath`, `UpdatePathNode`, `path_secret` chain, per-node HPKE keypair derivation, `commit_secret` at the root | § 7.4, § 7.6 | [`tree/update_path.go`](tree/update_path.go), [`group/update_path.go`](group/update_path.go) |
| `LeafNodeTBS` Ed25519 signature on the committer leaf, joiner-side verification | § 5.1.6, § 7.2 | [`group/update_path.go`](group/update_path.go) |
| `KeyPackage` Ed25519 signature, `AddMember` rejects tampered KeyPackages | § 5.1.6, § 10 | [`group/keypackage.go`](group/keypackage.go) |
| Group creation, Add proposals, Commit, joining via Welcome, HPKE-sealed `joiner_secret` | § 12.1, § 12.4 | [`group/state.go`](group/state.go), [`group/welcome.go`](group/welcome.go) |
| Key schedule: `joiner_secret`, `member_secret`, `epoch_secret`, `init_secret`, `confirmation_key`, `membership_key`, `epoch_authenticator` | § 8.1 | [`group/schedule.go`](group/schedule.go) |
| End-to-end smoke test wired into CI | — | [`cmd/mls-smoketest/`](cmd/mls-smoketest/) |

## Quick start

```sh
go get github.com/Deln0r/mls-go
```

A creator, two joiners, one commit, three matching `epoch_secret` values:

```go
package main

import (
    "bytes"
    "fmt"
    "log"

    "github.com/Deln0r/mls-go/group"
)

func main() {
    alice, _ := group.GenerateKeyPackage("alice")
    bob, _ := group.GenerateKeyPackage("bob")
    charlie, _ := group.GenerateKeyPackage("charlie")

    aliceState, _ := group.Create(alice, []byte("demo-group"))
    if err := aliceState.AddMember(bob.Public); err != nil {
        log.Fatal(err)
    }
    if err := aliceState.AddMember(charlie.Public); err != nil {
        log.Fatal(err)
    }
    welcomes, err := aliceState.Commit()
    if err != nil {
        log.Fatal(err)
    }

    bobState, _ := group.Join(bob, welcomes[0])
    charlieState, _ := group.Join(charlie, welcomes[1])

    fmt.Println("alice  :", aliceState.Keys.EpochSecret[:8])
    fmt.Println("bob    :", bobState.Keys.EpochSecret[:8])
    fmt.Println("charlie:", charlieState.Keys.EpochSecret[:8])
    if !bytes.Equal(aliceState.Keys.EpochSecret, bobState.Keys.EpochSecret) ||
        !bytes.Equal(aliceState.Keys.EpochSecret, charlieState.Keys.EpochSecret) {
        log.Fatal("epoch_secret divergence")
    }
}
```

## Architecture

```
mls-go/
├── encoding/mlstls/   TLS presentation language codec (§ 2.1)
├── crypto/            MTI ciphersuite primitives (§ 5)
├── tree/              Ratchet tree: math, state, hash, UpdatePath (§ 7)
├── group/             Group lifecycle, key schedule, Welcome (§ 8, § 10, § 12)
└── cmd/mls-smoketest/ End-to-end 3-member smoke test, wired into CI
```

Each package is independently testable. `encoding/mlstls` has no dependencies inside the repo; `crypto` depends only on `mlstls`; `tree` depends on `crypto` and `mlstls`; `group` depends on `tree`, `crypto`, and `mlstls`.

## Smoke test

```sh
make test       # all packages, race detector enabled
make smoketest  # 3-member end-to-end, asserts matching epoch_secret
```

The smoke test runs on every CI push and asserts that the creator and two joiners derive the same `epoch_secret`, `init_secret`, and `epoch_authenticator` after a 4-leaf-slot ratchet tree is established.

## Ciphersuite

Currently `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (the mandatory-to-implement suite from RFC 9420 § 5). Additional ciphersuites are tracked in [Roadmap](#roadmap).

## Roadmap

In rough priority order:

1. `FramedContent` encoding and the full RFC 9420 § 8.2 `confirmed_transcript_hash` chain.
2. Conformance against the [mls-implementations](https://github.com/mlswg/mls-implementations) test vector corpus.
3. Cross-impl interop CI matrix against [openmls](https://github.com/openmls/openmls), [cisco/mlspp](https://github.com/cisco/mlspp), and [ts-mls](https://github.com/LukaJCB/ts-mls).
4. Additional ciphersuites: P-256, P-384, P-521, X448, ChaCha20-Poly1305 variants.
5. Application data encryption: `PrivateMessage` framing with sender-data and content-encryption keys derived from the secret tree.
6. Mobile bindings via `gomobile` (iOS XCFramework, Android AAR).

## References

- [RFC 9420 — Messaging Layer Security (MLS)](https://datatracker.ietf.org/doc/rfc9420/)
- [RFC 9180 — Hybrid Public Key Encryption (HPKE)](https://datatracker.ietf.org/doc/rfc9180/)
- [RFC 9000 § 16 — variable-length integer encoding](https://www.rfc-editor.org/rfc/rfc9000.html#section-16)
- [openmls/openmls](https://github.com/openmls/openmls) — Rust reference
- [cisco/mlspp](https://github.com/cisco/mlspp) — C++ reference (Cisco WebEx)
- [LukaJCB/ts-mls](https://github.com/LukaJCB/ts-mls) — TypeScript reference
- [mls-implementations test corpus](https://github.com/mlswg/mls-implementations)

## Contributing

Bug reports and PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). For larger contributions or design questions, please open an issue first to discuss scope.

## Acknowledgements

- The IETF MLS working group, who shipped a remarkably clear specification.
- The [openmls](https://github.com/openmls/openmls) and [cisco/mlspp](https://github.com/cisco/mlspp) maintainers, whose source served as an executable reference where the spec text was ambiguous. Divergences from the spec in this codebase are mls-go bugs, not theirs.

## License

MIT. See [LICENSE](LICENSE).
