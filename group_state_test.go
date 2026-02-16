package mls

import (
	"bytes"
	"testing"
)

func TestGroupState_MarshalRoundtrip(t *testing.T) {
	cs := CipherSuiteMLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519

	credential := NewBasicCredential([]byte("alice"))
	kpp, err := GenerateKeyPairPackage(cs, credential)
	if err != nil {
		t.Fatal(err)
	}

	group, err := CreateGroup(GroupID("test-group"), kpp)
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt a message to advance the ratchet state.
	plaintext := []byte("hello world")
	ciphertext, err := group.CreateApplicationMessage(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Marshal the group.
	data, err := group.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if len(data) == 0 {
		t.Fatal("marshaled data is empty")
	}

	// Unmarshal into a new group.
	restored, err := UnmarshalGroupState(data)
	if err != nil {
		t.Fatal(err)
	}

	// Re-marshal and verify byte-level equality.
	data2, err := restored.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data, data2) {
		t.Fatal("re-marshaled data does not match original")
	}

	// The original group should be able to decrypt its own message (single-member group).
	decrypted, err := restored.UnmarshalAndProcessMessage(ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestGroupState_TwoMemberRoundtrip(t *testing.T) {
	cs := CipherSuiteMLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519

	// Create creator group.
	aliceCred := NewBasicCredential([]byte("alice"))
	aliceKPP, err := GenerateKeyPairPackage(cs, aliceCred)
	if err != nil {
		t.Fatal(err)
	}

	aliceGroup, err := CreateGroup(GroupID("two-member"), aliceKPP)
	if err != nil {
		t.Fatal(err)
	}

	// Generate Bob's key package.
	bobCred := NewBasicCredential([]byte("bob"))
	bobKPP, err := GenerateKeyPairPackage(cs, bobCred)
	if err != nil {
		t.Fatal(err)
	}

	// Alice adds Bob.
	welcome, commitBytes, err := aliceGroup.CreateWelcome([]KeyPackage{bobKPP.Public})
	if err != nil {
		t.Fatal(err)
	}

	// Alice processes her own commit.
	if _, err := aliceGroup.UnmarshalAndProcessMessage(commitBytes); err != nil {
		t.Fatal(err)
	}

	// Bob joins from welcome.
	bobGroup, err := GroupFromWelcome(welcome, bobKPP)
	if err != nil {
		t.Fatal(err)
	}

	// Marshal/unmarshal Bob's group.
	bobData, err := bobGroup.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	restoredBob, err := UnmarshalGroupState(bobData)
	if err != nil {
		t.Fatal(err)
	}

	// Alice sends a message, restored Bob decrypts it.
	plaintext := []byte("hello from alice")
	ciphertext, err := aliceGroup.CreateApplicationMessage(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := restoredBob.UnmarshalAndProcessMessage(ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}

	// Also marshal/unmarshal Alice's group and verify she can still encrypt.
	aliceData, err := aliceGroup.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	restoredAlice, err := UnmarshalGroupState(aliceData)
	if err != nil {
		t.Fatal(err)
	}

	plaintext2 := []byte("hello from restored alice")
	ciphertext2, err := restoredAlice.CreateApplicationMessage(plaintext2)
	if err != nil {
		t.Fatal(err)
	}

	// Restored Bob should decrypt the new message from restored Alice.
	// But first we need a fresh Bob since the previous restoredBob already
	// advanced state by decrypting. Re-unmarshal from the saved data.
	restoredBob2, err := UnmarshalGroupState(bobData)
	if err != nil {
		t.Fatal(err)
	}
	// First process the message from original Alice
	if _, err := restoredBob2.UnmarshalAndProcessMessage(ciphertext); err != nil {
		t.Fatal(err)
	}
	// Then the message from restored Alice
	decrypted2, err := restoredBob2.UnmarshalAndProcessMessage(ciphertext2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decrypted2, plaintext2) {
		t.Fatalf("decrypted2 = %q, want %q", decrypted2, plaintext2)
	}
}

func TestGroupState_EmptyPendingProposals(t *testing.T) {
	cs := CipherSuiteMLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519

	credential := NewBasicCredential([]byte("alice"))
	kpp, err := GenerateKeyPairPackage(cs, credential)
	if err != nil {
		t.Fatal(err)
	}

	group, err := CreateGroup(GroupID("empty-proposals"), kpp)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the group starts with no pending proposals.
	if len(group.pendingProposals) != 0 {
		t.Fatalf("expected 0 pending proposals, got %d", len(group.pendingProposals))
	}

	data, err := group.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	restored, err := UnmarshalGroupState(data)
	if err != nil {
		t.Fatal(err)
	}

	if len(restored.pendingProposals) != 0 {
		t.Fatalf("restored group has %d pending proposals, want 0", len(restored.pendingProposals))
	}

	// Verify the restored group can still encrypt.
	plaintext := []byte("still works")
	ciphertext, err := restored.CreateApplicationMessage(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt with original group.
	decrypted, err := group.UnmarshalAndProcessMessage(ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted = %q, want %q", decrypted, plaintext)
	}
}
