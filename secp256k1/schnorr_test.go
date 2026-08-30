package secp256k1

import "testing"

func TestSignSchnorrVerifyRoundTrip(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	sig, err := SignSchnorr(priv, testMsg)
	if err != nil {
		t.Fatalf("SignSchnorr failed: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("SignSchnorr produced %d bytes, want 64", len(sig))
	}

	if !VerifySchnorr(pub, testMsg, sig) {
		t.Error("VerifySchnorr rejected a signature it just produced")
	}
}

func TestSignSchnorrEmptyMessage(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	// Unlike ECDSA, Schnorr allows a zero-length message.
	sig, err := SignSchnorr(priv, nil)
	if err != nil {
		t.Fatalf("SignSchnorr failed for an empty message: %v", err)
	}
	if !VerifySchnorr(pub, nil, sig) {
		t.Error("VerifySchnorr rejected a signature over an empty message")
	}
}

func TestSignSchnorrIsDeterministic(t *testing.T) {
	priv := seckeyOne(t)

	sig1, err := SignSchnorr(priv, testMsg)
	if err != nil {
		t.Fatalf("SignSchnorr failed: %v", err)
	}
	sig2, err := SignSchnorr(priv, testMsg)
	if err != nil {
		t.Fatalf("SignSchnorr failed: %v", err)
	}

	if string(sig1) != string(sig2) {
		t.Error("SignSchnorr produced different signatures for the same key/message")
	}
}

func TestSignSchnorrHedgedVaries(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	var aux1, aux2 [32]byte
	aux1[0] = 0x01
	aux2[0] = 0x02

	sig1, err := SignSchnorrHedged(priv, testMsg, &aux1)
	if err != nil {
		t.Fatalf("SignSchnorrHedged failed: %v", err)
	}
	sig2, err := SignSchnorrHedged(priv, testMsg, &aux2)
	if err != nil {
		t.Fatalf("SignSchnorrHedged failed: %v", err)
	}

	if string(sig1) == string(sig2) {
		t.Error("SignSchnorrHedged produced identical signatures for different aux_rand")
	}
	if !VerifySchnorr(pub, testMsg, sig1) || !VerifySchnorr(pub, testMsg, sig2) {
		t.Error("VerifySchnorr rejected a hedged signature it should accept")
	}
}

func TestVerifySchnorrRejectsWrongKeyMessageAndLength(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	otherPriv, err := PrivateKeyFromBytes(append(make([]byte, 31), 2))
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed: %v", err)
	}
	otherPub, err := otherPriv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	sig, err := SignSchnorr(priv, testMsg)
	if err != nil {
		t.Fatalf("SignSchnorr failed: %v", err)
	}

	if VerifySchnorr(otherPub, testMsg, sig) {
		t.Error("VerifySchnorr accepted a signature under the wrong public key")
	}
	if VerifySchnorr(pub, []byte("a different message"), sig) {
		t.Error("VerifySchnorr accepted a signature over the wrong message")
	}
	if VerifySchnorr(pub, testMsg, sig[:len(sig)-1]) {
		t.Error("VerifySchnorr accepted a truncated signature")
	}
}
