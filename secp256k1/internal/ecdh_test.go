package internal

import "testing"

func TestECDHSymmetric(t *testing.T) {
	keyA := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	keyB := seckey(t, "0000000000000000000000000000000000000000000000000000000000000002")

	pubA, ok := PubkeyCreateCompressed(keyA)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}
	pubB, ok := PubkeyCreateCompressed(keyB)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	// The actual Diffie-Hellman property: seckeyA*pubkeyB and seckeyB*pubkeyA
	// are the same point, so both sides must derive the same shared secret.
	secretAB, ok := ECDH(pubB[:], keyA)
	if !ok {
		t.Fatal("ECDH failed for valid inputs")
	}
	secretBA, ok := ECDH(pubA[:], keyB)
	if !ok {
		t.Fatal("ECDH failed for valid inputs")
	}

	if secretAB != secretBA {
		t.Error("ECDH(pubB, seckeyA) != ECDH(pubA, seckeyB)")
	}
}

func TestECDHRejectsEmptyPubkey(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")

	if _, ok := ECDH(nil, key); ok {
		t.Error("ECDH succeeded with an empty public key")
	}
}

func TestECDHDoesNotAllocate(t *testing.T) {
	keyA := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	keyB := seckey(t, "0000000000000000000000000000000000000000000000000000000000000002")
	pubB, ok := PubkeyCreateCompressed(keyB)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	if got := testing.AllocsPerRun(100, func() { ECDH(pubB[:], keyA) }); got != 0 {
		t.Errorf("ECDH allocated %v times per run, want 0", got)
	}
}
