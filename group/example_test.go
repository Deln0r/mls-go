package group_test

import (
	"bytes"
	"fmt"

	"github.com/Deln0r/mls-go/group"
)

// Example_threeMember exercises the end-to-end flow that ships in the
// cmd/mls-smoketest binary: a creator generates a KeyPackage, two
// prospective joiners do the same, the creator stages Add proposals
// for both and commits, and each joiner runs the joiner-side key
// schedule against the resulting Welcome. All three derive the same
// epoch_secret.
func Example_threeMember() {
	alice, _ := group.GenerateKeyPackage("alice")
	bob, _ := group.GenerateKeyPackage("bob")
	charlie, _ := group.GenerateKeyPackage("charlie")

	aliceState, _ := group.Create(alice, []byte("demo-group"))
	if err := aliceState.AddMember(bob.Public); err != nil {
		panic(err)
	}
	if err := aliceState.AddMember(charlie.Public); err != nil {
		panic(err)
	}
	welcomes, err := aliceState.Commit()
	if err != nil {
		panic(err)
	}

	bobState, err := group.Join(bob, welcomes[0])
	if err != nil {
		panic(err)
	}
	charlieState, err := group.Join(charlie, welcomes[1])
	if err != nil {
		panic(err)
	}

	allMatch := bytes.Equal(aliceState.Keys.EpochSecret, bobState.Keys.EpochSecret) &&
		bytes.Equal(aliceState.Keys.EpochSecret, charlieState.Keys.EpochSecret)
	fmt.Println("epoch_secret agreed:", allMatch)
	fmt.Println("tree width:", aliceState.Tree.Width())
	// Output:
	// epoch_secret agreed: true
	// tree width: 7
}

// ExampleKeyPackage_Verify shows that a tampered KeyPackage is
// rejected: flipping a byte in the identity field after signing
// invalidates the embedded Ed25519 signature.
func ExampleKeyPackage_Verify() {
	bob, _ := group.GenerateKeyPackage("bob")
	fmt.Println("honest verify:", bob.Public.Verify())

	tampered := bob.Public
	tampered.Identity = []byte("not-bob")
	fmt.Println("tampered verify:", tampered.Verify() == nil)
	// Output:
	// honest verify: <nil>
	// tampered verify: false
}
