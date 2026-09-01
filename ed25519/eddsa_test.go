package ed25519

import (
	"crypto/sha512"
	"errors"
	"testing"
)

// TestSignMatchesRFC8032Vector1 checks Sign against RFC 8032 §7.1 test
// vector 1 (the empty-message case) — an external, standard test vector
// rather than only a round trip against this package's own Verify.
func TestSignMatchesRFC8032Vector1(t *testing.T) {
	priv := seckeyOne(t)
	sig := Sign(priv, []byte{})
	if sig != [SignatureLen]byte(rfc8032Test1Sig) {
		t.Errorf("Sign(seed, \"\") = %x, want %x", sig, rfc8032Test1Sig)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv := seckeyOne(t)
	pub := priv.PublicKey()

	sig := Sign(priv, testMsg)
	if !Verify(pub, testMsg, sig[:]) {
		t.Error("Verify rejected a signature Sign just produced")
	}
}

func TestSignIsDeterministic(t *testing.T) {
	priv := seckeyOne(t)
	sig1 := Sign(priv, testMsg)
	sig2 := Sign(priv, testMsg)
	if sig1 != sig2 {
		t.Error("Sign produced two different signatures for the same key and message")
	}
}

func TestVerifyRejectsWrongMessageAndKey(t *testing.T) {
	priv := seckeyOne(t)
	pub := priv.PublicKey()
	otherPub := seckeyN(t, 2).PublicKey()

	sig := Sign(priv, testMsg)

	if Verify(pub, append(append([]byte{}, testMsg...), 0x00), sig[:]) {
		t.Error("Verify accepted a signature under a modified message")
	}
	if Verify(otherPub, testMsg, sig[:]) {
		t.Error("Verify accepted a signature under the wrong public key")
	}
}

func TestSignCtxVerifyCtxRoundTrip(t *testing.T) {
	priv := seckeyOne(t)
	pub := priv.PublicKey()
	context := []byte("example context")

	sig, err := SignCtx(priv, testMsg, context)
	if err != nil {
		t.Fatalf("SignContext failed: %v", err)
	}
	if !VerifyCtx(pub, testMsg, context, sig[:]) {
		t.Error("VerifyContext rejected a signature SignContext just produced")
	}
}

func TestVerifyCtxRejectsWrongContext(t *testing.T) {
	priv := seckeyOne(t)
	pub := priv.PublicKey()

	sig, err := SignCtx(priv, testMsg, []byte("context A"))
	if err != nil {
		t.Fatalf("SignContext failed: %v", err)
	}
	if VerifyCtx(pub, testMsg, []byte("context B"), sig[:]) {
		t.Error("VerifyContext accepted a signature under the wrong context string")
	}
	// A ctx-variant signature must not verify as a plain-Ed25519 signature
	// either — they are domain-separated, not just optionally tagged.
	if Verify(pub, testMsg, sig[:]) {
		t.Error("Verify (pure Ed25519) accepted an Ed25519ctx signature")
	}
}

func TestSignCtxRejectsOversizeContext(t *testing.T) {
	priv := seckeyOne(t)
	if _, err := SignCtx(priv, testMsg, make([]byte, 256)); err == nil {
		t.Error("SignContext accepted a 256-byte context string (RFC 8032 limit is 255)")
	}
}

func TestSignPhVerifyPhRoundTrip(t *testing.T) {
	priv := seckeyOne(t)
	pub := priv.PublicKey()
	digest := sha512.Sum512(testMsg)
	context := []byte("example context")

	sig, err := SignPh(priv, digest, context)
	if err != nil {
		t.Fatalf("SignPh failed: %v", err)
	}
	if !VerifyPh(pub, digest, context, sig[:]) {
		t.Error("VerifyPh rejected a signature SignPh just produced")
	}
}

func TestSignPhWithEmptyContextRoundTrip(t *testing.T) {
	priv := seckeyOne(t)
	pub := priv.PublicKey()
	digest := sha512.Sum512(testMsg)

	sig, err := SignPh(priv, digest, nil)
	if err != nil {
		t.Fatalf("SignPh failed: %v", err)
	}
	if !VerifyPh(pub, digest, nil, sig[:]) {
		t.Error("VerifyPh rejected a signature SignPh just produced")
	}
}

func TestVerifyPhRejectsWrongDigestAndContext(t *testing.T) {
	priv := seckeyOne(t)
	pub := priv.PublicKey()
	digest := sha512.Sum512(testMsg)
	otherDigest := sha512.Sum512(append(append([]byte{}, testMsg...), 0x00))
	context := []byte("example context")

	sig, err := SignPh(priv, digest, context)
	if err != nil {
		t.Fatalf("SignPh failed: %v", err)
	}
	if VerifyPh(pub, otherDigest, context, sig[:]) {
		t.Error("VerifyPh accepted a signature under the wrong digest")
	}
	if VerifyPh(pub, digest, []byte("different context"), sig[:]) {
		t.Error("VerifyPh accepted a signature under the wrong context string")
	}
}

func TestSignContextRejectsEmptyContext(t *testing.T) {
	priv := seckeyOne(t)
	if _, err := SignCtx(priv, testMsg, nil); !errors.Is(err, ErrContextRequired) {
		t.Errorf("SignContext with nil context: error = %v, want %v", err, ErrContextRequired)
	}
	if _, err := SignCtx(priv, testMsg, []byte{}); !errors.Is(err, ErrContextRequired) {
		t.Errorf("SignContext with empty context: error = %v, want %v", err, ErrContextRequired)
	}
}

func TestVerifyContextRejectsEmptyContext(t *testing.T) {
	priv := seckeyOne(t)
	pub := priv.PublicKey()

	// A pure Ed25519 signature must not verify under VerifyContext with an
	// empty context — crypto/ed25519 would otherwise silently treat that
	// as plain Ed25519 and accept it, defeating the whole point of a
	// separately named context-verification function.
	sig := Sign(priv, testMsg)
	if VerifyCtx(pub, testMsg, nil, sig[:]) {
		t.Error("VerifyContext with an empty context accepted a plain-Ed25519 signature")
	}
}
