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
	aliceState.AddMember(bob.Public)
	aliceState.AddMember(charlie.Public)
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
	st.AddMember(bob.Public)
	welcomes, err := st.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Join(mallory, welcomes[0]); err == nil {
		t.Fatalf("mallory Join should have failed")
	}
}

func TestEpochSecretChangesEachCommit(t *testing.T) {
	alice, _ := GenerateKeyPackage("alice")
	bob, _ := GenerateKeyPackage("bob")
	charlie, _ := GenerateKeyPackage("charlie")

	st, _ := Create(alice, []byte("g"))
	first := append([]byte(nil), st.Keys.EpochSecret...)

	st.AddMember(bob.Public)
	if _, err := st.Commit(); err != nil {
		t.Fatal(err)
	}
	second := append([]byte(nil), st.Keys.EpochSecret...)
	if bytes.Equal(first, second) {
		t.Errorf("epoch_secret unchanged after first commit")
	}

	st.AddMember(charlie.Public)
	if _, err := st.Commit(); err != nil {
		t.Fatal(err)
	}
	third := append([]byte(nil), st.Keys.EpochSecret...)
	if bytes.Equal(second, third) {
		t.Errorf("epoch_secret unchanged after second commit")
	}
}
