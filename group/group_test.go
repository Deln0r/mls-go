package group

import (
	"bytes"
	"testing"
)

func TestThreeMemberSmokeDeriveSameEpochSecret(t *testing.T) {
	alice, err := GenerateKeyPackage("alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := GenerateKeyPackage("bob")
	if err != nil {
		t.Fatal(err)
	}
	charlie, err := GenerateKeyPackage("charlie")
	if err != nil {
		t.Fatal(err)
	}

	aliceState, err := Create(alice, []byte("test-group"))
	if err != nil {
		t.Fatal(err)
	}
	if err := aliceState.AddMember(bob.Public); err != nil {
		t.Fatal(err)
	}
	if err := aliceState.AddMember(charlie.Public); err != nil {
		t.Fatal(err)
	}
	welcomes, err := aliceState.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if len(welcomes) != 2 {
		t.Fatalf("got %d welcomes, want 2", len(welcomes))
	}

	bobState, err := Join(bob, welcomes[0])
	if err != nil {
		t.Fatalf("bob Join: %v", err)
	}
	charlieState, err := Join(charlie, welcomes[1])
	if err != nil {
		t.Fatalf("charlie Join: %v", err)
	}

	if !bytes.Equal(aliceState.Keys.EpochSecret, bobState.Keys.EpochSecret) {
		t.Errorf("alice and bob epoch_secret differ:\n  alice = %x\n  bob   = %x",
			aliceState.Keys.EpochSecret, bobState.Keys.EpochSecret)
	}
	if !bytes.Equal(aliceState.Keys.EpochSecret, charlieState.Keys.EpochSecret) {
		t.Errorf("alice and charlie epoch_secret differ:\n  alice   = %x\n  charlie = %x",
			aliceState.Keys.EpochSecret, charlieState.Keys.EpochSecret)
	}

	// Sanity: also confirm every other derived secret matches.
	if !bytes.Equal(aliceState.Keys.InitSecret, bobState.Keys.InitSecret) {
		t.Errorf("init_secret differs between alice and bob")
	}
	if !bytes.Equal(aliceState.Keys.ConfirmationKey, bobState.Keys.ConfirmationKey) {
		t.Errorf("confirmation_key differs between alice and bob")
	}
	if !bytes.Equal(aliceState.Keys.EpochAuthenticator, charlieState.Keys.EpochAuthenticator) {
		t.Errorf("epoch_authenticator differs between alice and charlie")
	}

	// Tree shape: width 7 (4 leaf slots, 3 populated, leaf index 3 blank).
	if aliceState.Tree.Width() != 7 {
		t.Errorf("alice tree width %d, want 7", aliceState.Tree.Width())
	}
	if bobState.Tree.Width() != 7 {
		t.Errorf("bob tree width %d, want 7", bobState.Tree.Width())
	}
}

func TestJoinRejectsWrongRecipient(t *testing.T) {
	alice, _ := GenerateKeyPackage("alice")
	bob, _ := GenerateKeyPackage("bob")
	mallory, _ := GenerateKeyPackage("mallory")

	st, err := Create(alice, []byte("group"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddMember(bob.Public); err != nil {
		t.Fatal(err)
	}
	welcomes, err := st.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Join(mallory, welcomes[0]); err == nil {
		t.Fatalf("mallory Join should have failed")
	}
}

func TestCommitProducesNonZeroPathSecret(t *testing.T) {
	alice, _ := GenerateKeyPackage("alice")
	bob, _ := GenerateKeyPackage("bob")

	st, _ := Create(alice, []byte("g"))
	preCommitInit := append([]byte(nil), st.Keys.InitSecret...)

	if err := st.AddMember(bob.Public); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Commit(); err != nil {
		t.Fatal(err)
	}

	// After a real commit with an UpdatePath, init_secret must differ from
	// the pre-commit state. (If commit_secret were still all-zero, the
	// derivation would only differ via the GroupContext bytes; we want
	// evidence that path_secret actually fed the schedule.)
	if bytes.Equal(preCommitInit, st.Keys.InitSecret) {
		t.Fatalf("init_secret unchanged after commit: path_secret chain did not feed key schedule")
	}

	// The committer's leaf encryption key must have rotated.
	leaf, _ := st.Tree.Leaf(0)
	if leaf == nil {
		t.Fatalf("alice leaf vanished")
	}
	if bytes.Equal(leaf.EncryptionKey, alice.Public.InitKey) {
		t.Fatalf("committer leaf EncryptionKey not rotated after commit")
	}
}

func TestAddMemberRejectsTamperedKeyPackage(t *testing.T) {
	alice, _ := GenerateKeyPackage("alice")
	bob, _ := GenerateKeyPackage("bob")

	st, _ := Create(alice, []byte("g"))

	// Tamper with bob's identity after signing.
	tampered := bob.Public
	tampered.Identity = []byte("not-bob")
	if err := st.AddMember(tampered); err == nil {
		t.Fatalf("AddMember should reject tampered KeyPackage")
	}

	// Honest KeyPackage still accepted.
	if err := st.AddMember(bob.Public); err != nil {
		t.Fatalf("AddMember rejected honest KeyPackage: %v", err)
	}
}

func TestEpochSecretChangesEachCommit(t *testing.T) {
	alice, _ := GenerateKeyPackage("alice")
	bob, _ := GenerateKeyPackage("bob")
	charlie, _ := GenerateKeyPackage("charlie")

	st, _ := Create(alice, []byte("g"))
	first := append([]byte(nil), st.Keys.EpochSecret...)

	if err := st.AddMember(bob.Public); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Commit(); err != nil {
		t.Fatal(err)
	}
	second := append([]byte(nil), st.Keys.EpochSecret...)
	if bytes.Equal(first, second) {
		t.Errorf("epoch_secret unchanged after first commit")
	}

	if err := st.AddMember(charlie.Public); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Commit(); err != nil {
		t.Fatal(err)
	}
	third := append([]byte(nil), st.Keys.EpochSecret...)
	if bytes.Equal(second, third) {
		t.Errorf("epoch_secret unchanged after second commit")
	}
}
