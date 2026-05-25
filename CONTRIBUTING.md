# Contributing to mls-go

Thanks for considering a contribution. The maintainer is a single individual building this in spare time; capacity is limited. Reading this whole document before opening anything saves everyone time.

## Scope

mls-go ports a subset of RFC 9420 (MLS) to Go:

- **In scope:** the TLS presentation wire codec, the MTI ciphersuite (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`), the array-based ratchet tree, TreeKEM (UpdatePath + path-secret chain), the RFC 9420 § 8.1 key schedule, KeyPackage / Welcome / Commit handling, and pure-Go testing infrastructure.
- **Out of scope right now:** additional ciphersuites, `PrivateMessage` framing, application data encryption, mobile bindings, fuzz harnesses, persistent storage backends. These are tracked in the [README Roadmap](README.md#roadmap). PRs that try to start any of these will be politely asked to wait until the relevant roadmap item is opened up.
- **Out of scope permanently:** features outside the MLS protocol family or its IETF dependencies.

If you are unsure whether something is in scope, open an issue first.

## Bug reports

Useful bug reports include:

1. The version (commit SHA or release tag).
2. Minimal Go code that reproduces the issue.
3. Expected vs observed behavior.
4. If a byte-encoding bug: hex dumps of input + expected + actual output. If a cross-impl divergence vs openmls / mlspp / ts-mls, include the equivalent output from the other implementation.

Cross-implementation interop bugs are highest priority.

## Pull requests

Before opening a PR:

- Run `make test` (all packages must stay green under `-race`).
- Run `make smoketest` (the 3-member end-to-end must stay zero-fail).
- Run `gofmt -s -w .` on changed files.
- Add a test that fails without the change and passes with it.

Commit message format: one short subject line under 70 characters, then a blank line, then a body explaining the *why*. Example:

```
group: reject Welcome whose confirmation_tag does not verify

Without this check a tampered GroupInfo could install a joiner in the
group with an arbitrary confirmation_key, breaking RFC 9420 § 12.4.3.
A new test exercises a flipped byte inside the confirmation_tag.
```

PRs that add or modify wire encoders MUST include a roundtrip test in the same package.

### Authorship

This project uses standard git authorship. Please do not include AI-agent attribution lines (`Co-Authored-By: Claude`, `🤖 Generated with [Claude Code]`, `noreply@anthropic.com`, etc.) in commit messages. PRs containing such trailers will be asked to amend.

## Code style

- Standard `gofmt`. `go vet ./...` must pass.
- Idiomatic Go: no Rust-style transliteration. Generics only where the Go standard library already uses them.
- No cgo. The whole project depends on `go build` + a couple of stdlib subpackages; please keep it that way.
- Public API stability is not yet a priority; breaking changes are accepted until v1.0.
- Comments: `doc.go` for each package, godoc on all exported symbols. Short, not essays.

## Security disclosure

For security-relevant issues (signature forgery, key derivation flaws, panics on attacker-supplied input, side-channel risks), please email the maintainer privately first rather than opening a public issue. Once a fix is ready we will publish the fix and a CVE-style note together.

## Maintainer expectations

The maintainer is a single individual building this in spare time. Response times will vary. PRs may take a week or two to review. If something has been quiet for over a month, please ping politely on the original thread.

## License

By contributing you agree your contributions are licensed under MIT, matching the project license.
