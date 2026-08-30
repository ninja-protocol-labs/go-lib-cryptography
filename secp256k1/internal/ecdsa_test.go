package internal

import (
	"encoding/hex"
	"testing"
)

func msg32(t *testing.T, s string) *[MessageLen]byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in test case: %v", err)
	}
	if len(b) != MessageLen {
		t.Fatalf("test case is %d bytes, want %d", len(b), MessageLen)
	}

	var m [MessageLen]byte
	copy(m[:], b)
	return &m
}

const testMsg = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestECDSASignVerifyRoundTrip(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)

	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	sig, ok := ECDSASignCompact(m, key)
	if !ok {
		t.Fatal("ECDSASignCompact failed for valid inputs")
	}

	if !ECDSAVerifyCompact(m, pub[:], &sig, false) {
		t.Error("ECDSAVerifyCompact rejected a signature it just produced")
	}
}

func TestECDSASignCompactIsDeterministic(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)

	sig1, ok := ECDSASignCompact(m, key)
	if !ok {
		t.Fatal("ECDSASignCompact failed for valid inputs")
	}
	sig2, ok := ECDSASignCompact(m, key)
	if !ok {
		t.Fatal("ECDSASignCompact failed for valid inputs")
	}

	if sig1 != sig2 {
		t.Error("ECDSASignCompact produced different signatures for the same msg/seckey pair")
	}
}

func TestECDSASignCompactHedgedVaries(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)

	var aux1, aux2 [32]byte
	aux1[0] = 0x01
	aux2[0] = 0x02

	sig1, ok := ECDSASignCompactHedged(m, key, &aux1)
	if !ok {
		t.Fatal("ECDSASignCompactHedged failed for valid inputs")
	}
	sig2, ok := ECDSASignCompactHedged(m, key, &aux2)
	if !ok {
		t.Fatal("ECDSASignCompactHedged failed for valid inputs")
	}

	if sig1 == sig2 {
		t.Error("ECDSASignCompactHedged produced identical signatures for different aux_rand")
	}

	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}
	if !ECDSAVerifyCompact(m, pub[:], &sig1, false) {
		t.Error("ECDSAVerifyCompact rejected a hedged signature it should accept")
	}
	if !ECDSAVerifyCompact(m, pub[:], &sig2, false) {
		t.Error("ECDSAVerifyCompact rejected a hedged signature it should accept")
	}
}

func TestECDSAVerifyCompactRejectsWrongKey(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	otherKey := seckey(t, "0000000000000000000000000000000000000000000000000000000000000002")
	m := msg32(t, testMsg)

	sig, ok := ECDSASignCompact(m, key)
	if !ok {
		t.Fatal("ECDSASignCompact failed for valid inputs")
	}

	otherPub, ok := PubkeyCreateCompressed(otherKey)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	if ECDSAVerifyCompact(m, otherPub[:], &sig, false) {
		t.Error("ECDSAVerifyCompact accepted a signature under the wrong public key")
	}
}

func TestECDSAVerifyCompactRejectsWrongMessage(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)
	otherMsg := msg32(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	sig, ok := ECDSASignCompact(m, key)
	if !ok {
		t.Fatal("ECDSASignCompact failed for valid inputs")
	}

	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	if ECDSAVerifyCompact(otherMsg, pub[:], &sig, false) {
		t.Error("ECDSAVerifyCompact accepted a signature over the wrong message")
	}
}

func TestECDSASignVerifyDoesNotAllocate(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)
	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	if got := testing.AllocsPerRun(100, func() { ECDSASignCompact(m, key) }); got != 0 {
		t.Errorf("ECDSASignCompact allocated %v times per run, want 0", got)
	}

	sig, _ := ECDSASignCompact(m, key)
	if got := testing.AllocsPerRun(100, func() { ECDSAVerifyCompact(m, pub[:], &sig, false) }); got != 0 {
		t.Errorf("ECDSAVerifyCompact allocated %v times per run, want 0", got)
	}
}
