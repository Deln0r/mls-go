// Package group implements the MLS group lifecycle: KeyPackage generation,
// group creation, staging Add proposals, committing them to advance the
// epoch, and joining a group via the Welcome message that the committer
// produced.
//
// The key schedule (joiner_secret, member_secret, epoch_secret, and the
// secrets derived from epoch_secret) follows RFC 9420 section 8.1. Group
// state is held in State; per-epoch keys live in EpochKeys.
package group
