package internal

import "testing"

func TestSchnorrSignVerifyRoundTrip(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)

	pub, _, ok := XonlyPubkeyCreate(key)
	if !ok {
		t.Fatal("XonlyPubkeyCreate failed for a valid key")
	}

	sig, ok := SchnorrSign(m[:], key)
	if !ok {
		t.Fatal("SchnorrSign failed for valid inputs")
	}

	if !SchnorrVerify(m[:], &pub, &sig) {
		t.Error("SchnorrVerify rejected a signature it just produced")
	}
}

func TestSchnorrSignEmptyMessage(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	pub, _, ok := XonlyPubkeyCreate(key)
	if !ok {
		t.Fatal("XonlyPubkeyCreate failed for a valid key")
	}

	// Unlike ECDSA (always a 32-byte digest), a Schnorr signature over this
	// scheme allows a zero-length message; shim_schnorr_sign must handle a
	// nil msg pointer correctly.
	sig, ok := SchnorrSign(nil, key)
	if !ok {
		t.Fatal("SchnorrSign failed for an empty message")
	}
	if !SchnorrVerify(nil, &pub, &sig) {
		t.Error("SchnorrVerify rejected a signature over an empty message")
	}
}

func TestSchnorrSignIsDeterministic(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)

	sig1, ok := SchnorrSign(m[:], key)
	if !ok {
		t.Fatal("SchnorrSign failed for valid inputs")
	}
	sig2, ok := SchnorrSign(m[:], key)
	if !ok {
		t.Fatal("SchnorrSign failed for valid inputs")
	}

	if sig1 != sig2 {
		t.Error("SchnorrSign produced different signatures for the same msg/seckey pair")
	}
}

func TestSchnorrSignHedgedVaries(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)
	pub, _, ok := XonlyPubkeyCreate(key)
	if !ok {
		t.Fatal("XonlyPubkeyCreate failed for a valid key")
	}

	var aux1, aux2 [32]byte
	aux1[0] = 0x01
	aux2[0] = 0x02

	sig1, ok := SchnorrSignHedged(m[:], key, &aux1)
	if !ok {
		t.Fatal("SchnorrSignHedged failed for valid inputs")
	}
	sig2, ok := SchnorrSignHedged(m[:], key, &aux2)
	if !ok {
		t.Fatal("SchnorrSignHedged failed for valid inputs")
	}

	if sig1 == sig2 {
		t.Error("SchnorrSignHedged produced identical signatures for different aux_rand")
	}
	if !SchnorrVerify(m[:], &pub, &sig1) {
		t.Error("SchnorrVerify rejected a hedged signature it should accept")
	}
	if !SchnorrVerify(m[:], &pub, &sig2) {
		t.Error("SchnorrVerify rejected a hedged signature it should accept")
	}
}

func TestSchnorrVerifyRejectsWrongMessageAndKey(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	otherKey := seckey(t, "0000000000000000000000000000000000000000000000000000000000000002")
	m := msg32(t, testMsg)
	otherMsg := msg32(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	pub, _, ok := XonlyPubkeyCreate(key)
	if !ok {
		t.Fatal("XonlyPubkeyCreate failed for a valid key")
	}
	otherPub, _, ok := XonlyPubkeyCreate(otherKey)
	if !ok {
		t.Fatal("XonlyPubkeyCreate failed for a valid key")
	}

	sig, ok := SchnorrSign(m[:], key)
	if !ok {
		t.Fatal("SchnorrSign failed for valid inputs")
	}

	if SchnorrVerify(otherMsg[:], &pub, &sig) {
		t.Error("SchnorrVerify accepted a signature over the wrong message")
	}
	if SchnorrVerify(m[:], &otherPub, &sig) {
		t.Error("SchnorrVerify accepted a signature under the wrong public key")
	}
}

func TestSchnorrSignVerifyDoesNotAllocate(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)
	pub, _, ok := XonlyPubkeyCreate(key)
	if !ok {
		t.Fatal("XonlyPubkeyCreate failed for a valid key")
	}

	if got := testing.AllocsPerRun(100, func() { SchnorrSign(m[:], key) }); got != 0 {
		t.Errorf("SchnorrSign allocated %v times per run, want 0", got)
	}

	sig, _ := SchnorrSign(m[:], key)
	if got := testing.AllocsPerRun(100, func() { SchnorrVerify(m[:], &pub, &sig) }); got != 0 {
		t.Errorf("SchnorrVerify allocated %v times per run, want 0", got)
	}
}
