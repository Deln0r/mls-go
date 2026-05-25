# mls-go

Pure-Go implementation of [RFC 9420](https://datatracker.ietf.org/doc/rfc9420/) — Messaging Layer Security (MLS), the IETF end-to-end encryption layer for group messaging.

## Overview

`mls-go` provides the cryptographic core, ratchet tree, and group lifecycle of an MLS stack:

- TLS presentation language codec with QUIC variable-length integer lengths (RFC 9420 § 2.1, RFC 9000 § 16).
- The `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` ciphersuite: SHA-256, HKDF, AES-128-GCM, Ed25519, and HPKE base mode over DHKEM(X25519, HKDF-SHA-256).
- Array-based left-balanced ratchet tree with the full node-math layer (level, parent, sibling, direct path, copath, resolution, common ancestor).
- Group lifecycle: KeyPackage generation, group creation, Add proposals, Commit, and joining via Welcome. The RFC 9420 § 8.1 key schedule is followed verbatim (`joiner_secret`, `epoch_secret`, `init_secret`, `confirmation_key`, `membership_key`, `epoch_authenticator`).

## Smoke test

`cmd/mls-smoketest` drives an end-to-end flow on every CI run: a creator stages two Add proposals, commits, and produces a Welcome per joiner; each joiner derives the same `epoch_secret`, `init_secret`, and `epoch_authenticator`.

## Layout

```
encoding/mlstls/      TLS presentation language codec
crypto/               Ciphersuite primitives (hash, HKDF, AEAD, signatures, HPKE)
tree/                 Ratchet tree math and state
group/                Group lifecycle, key schedule, Welcome
cmd/mls-smoketest/    3-member end-to-end smoke test
```

## Reference implementations

These are widely used as executable specifications for cross-checking behavior:

- [openmls/openmls](https://github.com/openmls/openmls) (Rust)
- [cisco/mlspp](https://github.com/cisco/mlspp) (C++)
- [LukaJCB/ts-mls](https://github.com/LukaJCB/ts-mls) (TypeScript)
- [mlswg/mls-implementations](https://github.com/mlswg/mls-implementations) (test vectors)

## Build and test

Requires Go 1.26 or newer.

```
go test ./...
go run ./cmd/mls-smoketest
```

## License

MIT, see [LICENSE](LICENSE).
