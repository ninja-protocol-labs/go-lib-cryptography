package secp256r1

import "testing"

func TestSignCompactVerifyCompactRoundTrip(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	sig, err := SignCompact(priv, testMsg)
	if err != nil {
		t.Fatalf("SignCompact failed: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("SignCompact produced %d bytes, want 64", len(sig))
	}

	if !VerifyCompact(pub, testMsg, sig) {
		t.Error("VerifyCompact rejected a signature it just produced")
	}
}

func TestSignDERVerifyDERRoundTrip(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	sig, err := SignDER(priv, testMsg)
	if err != nil {
		t.Fatalf("SignDER failed: %v", err)
	}

	if !VerifyDER(pub, testMsg, sig) {
		t.Error("VerifyDER rejected a signature it just produced")
	}
}

func TestSignDigestCompactRoundTrip(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	var digest [32]byte
	copy(digest[:], testMsg)

	sig, err := SignDigestCompact(priv, digest)
	if err != nil {
		t.Fatalf("SignDigestCompact failed: %v", err)
	}
	if !VerifyDigestCompact(pub, digest, sig) {
		t.Error("VerifyDigestCompact rejected a signature it just produced")
	}
}

func TestSignDigestDERRoundTrip(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	var digest [32]byte
	copy(digest[:], testMsg)

	sig, err := SignDigestDER(priv, digest)
	if err != nil {
		t.Fatalf("SignDigestDER failed: %v", err)
	}
	if !VerifyDigestDER(pub, digest, sig) {
		t.Error("VerifyDigestDER rejected a signature it just produced")
	}
}

// crypto/ecdsa.Sign always mixes fresh entropy in, unlike secp256k1's
// RFC-6979 default — so, unlike secp256k1's ECDSA tests, there is no
// "IsDeterministic" case to check here. This is the equivalent property:
// two signatures over the same input differ, and both still verify.
func TestSignCompactVariesButBothVerify(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	sig1, err := SignCompact(priv, testMsg)
	if err != nil {
		t.Fatalf("SignCompact failed: %v", err)
	}
	sig2, err := SignCompact(priv, testMsg)
	if err != nil {
		t.Fatalf("SignCompact failed: %v", err)
	}

	if string(sig1) == string(sig2) {
		t.Error("SignCompact produced identical signatures across two calls")
	}
	if !VerifyCompact(pub, testMsg, sig1) || !VerifyCompact(pub, testMsg, sig2) {
		t.Error("VerifyCompact rejected one of two independently-signed signatures")
	}
}

func TestVerifyCompactRejectsWrongKeyMessageAndLength(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	otherPub, err := seckeyN(t, 2).PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	sig, err := SignCompact(priv, testMsg)
	if err != nil {
		t.Fatalf("SignCompact failed: %v", err)
	}

	if VerifyCompact(otherPub, testMsg, sig) {
		t.Error("VerifyCompact accepted a signature under the wrong public key")
	}
	if VerifyCompact(pub, []byte("a different message"), sig) {
		t.Error("VerifyCompact accepted a signature over the wrong message")
	}
	if VerifyCompact(pub, testMsg, sig[:len(sig)-1]) {
		t.Error("VerifyCompact accepted a truncated signature")
	}
}

func TestVerifyDERRejectsWrongKeyAndMessage(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	otherPub, err := seckeyN(t, 2).PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	sig, err := SignDER(priv, testMsg)
	if err != nil {
		t.Fatalf("SignDER failed: %v", err)
	}

	if VerifyDER(otherPub, testMsg, sig) {
		t.Error("VerifyDER accepted a signature under the wrong public key")
	}
	if VerifyDER(pub, []byte("a different message"), sig) {
		t.Error("VerifyDER accepted a signature over the wrong message")
	}
}
