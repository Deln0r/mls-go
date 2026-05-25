// Command mls-smoketest exercises an end-to-end MLS group flow and exits
// non-zero on any divergence.
//
// Flow: Alice creates a singleton group, stages Add proposals for Bob and
// Charlie, commits, and produces a Welcome for each new joiner. Each joiner
// runs the joiner-side key schedule against the Welcome. The binary asserts
// that all three members derive the same epoch_secret, init_secret, and
// epoch_authenticator.
package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/Deln0r/mls-go/group"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "smoketest:", err)
		os.Exit(1)
	}
	fmt.Println("smoketest: alice + bob + charlie derived matching epoch_secret")
}

func run() error {
	alice, err := group.GenerateKeyPackage("alice")
	if err != nil {
		return fmt.Errorf("alice keypackage: %w", err)
	}
	bob, err := group.GenerateKeyPackage("bob")
	if err != nil {
		return fmt.Errorf("bob keypackage: %w", err)
	}
	charlie, err := group.GenerateKeyPackage("charlie")
	if err != nil {
		return fmt.Errorf("charlie keypackage: %w", err)
	}

	aliceState, err := group.Create(alice, []byte("smoketest-group"))
	if err != nil {
		return fmt.Errorf("alice create: %w", err)
	}
	aliceState.AddMember(bob.Public)
	aliceState.AddMember(charlie.Public)

	welcomes, err := aliceState.Commit()
	if err != nil {
		return fmt.Errorf("alice commit: %w", err)
	}
	if len(welcomes) != 2 {
		return fmt.Errorf("commit produced %d welcomes, want 2", len(welcomes))
	}

	bobState, err := group.Join(bob, welcomes[0])
	if err != nil {
		return fmt.Errorf("bob join: %w", err)
	}
	charlieState, err := group.Join(charlie, welcomes[1])
	if err != nil {
		return fmt.Errorf("charlie join: %w", err)
	}

	if !bytes.Equal(aliceState.Keys.EpochSecret, bobState.Keys.EpochSecret) {
		return fmt.Errorf("alice and bob epoch_secret differ:\n  alice = %x\n  bob   = %x",
			aliceState.Keys.EpochSecret, bobState.Keys.EpochSecret)
	}
	if !bytes.Equal(aliceState.Keys.EpochSecret, charlieState.Keys.EpochSecret) {
		return fmt.Errorf("alice and charlie epoch_secret differ:\n  alice   = %x\n  charlie = %x",
			aliceState.Keys.EpochSecret, charlieState.Keys.EpochSecret)
	}
	if !bytes.Equal(aliceState.Keys.InitSecret, bobState.Keys.InitSecret) {
		return fmt.Errorf("init_secret differs")
	}
	if !bytes.Equal(aliceState.Keys.EpochAuthenticator, charlieState.Keys.EpochAuthenticator) {
		return fmt.Errorf("epoch_authenticator differs")
	}
	if aliceState.Tree.Width() != 7 {
		return fmt.Errorf("alice tree width %d, want 7", aliceState.Tree.Width())
	}
	if bobState.Tree.Width() != 7 || charlieState.Tree.Width() != 7 {
		return fmt.Errorf("joiner tree widths %d/%d, want 7/7",
			bobState.Tree.Width(), charlieState.Tree.Width())
	}
	return nil
}
