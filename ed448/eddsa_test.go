package ed448

import (
	"bytes"
	"errors"
	"testing"
)

func TestSignMatchesRFC8032Vector1(t *testing.T) {
	priv := seckeyOne(t)
	sig, err := Sign(priv, []byte{}, nil)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if !bytes.Equal(sig, rfc8032Test1Sig) {
		t.Errorf("Sign(seed, \"\", nil) = %x, want %x", sig, rfc8032Test1Sig)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv := seckeyOne(t)
	pub := priv.PublicKey()

	sig, err := Sign(priv, testMsg, nil)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if !Verify(pub, testMsg, sig, nil) {
		t.Error("Verify rejected a signature Sign just produced")
	}
}

func TestSignIsDeterministic(t *testing.T) {
	priv := seckeyOne(t)
	sig1, err := Sign(priv, testMsg, nil)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	sig2, err := Sign(priv, testMsg, nil)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Error("Sign produced two different signatures for the same key and message")
	}
}

func TestVerifyRejectsWrongMessageKeyAndContext(t *testing.T) {
	priv := seckeyOne(t)
	pub := priv.PublicKey()
	otherPub := seckeyN(t, 2).PublicKey()
	context := []byte("example context")

	sig, err := Sign(priv, testMsg, context)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if Verify(pub, append(append([]byte{}, testMsg...), 0x00), sig, context) {
		t.Error("Verify accepted a signature under a modified message")
	}
	if Verify(otherPub, testMsg, sig, context) {
		t.Error("Verify accepted a signature under the wrong public key")
	}
	if Verify(pub, testMsg, sig, []byte("different context")) {
		t.Error("Verify accepted a signature under the wrong context")
	}
	if Verify(pub, testMsg, sig, nil) {
		t.Error("Verify accepted a context-signed signature with no context")
	}
}

func TestSignVerifyWithEmptyContextRoundTrip(t *testing.T) {
	priv := seckeyOne(t)
	pub := priv.PublicKey()

	sig, err := Sign(priv, testMsg, []byte{})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if !Verify(pub, testMsg, sig, []byte{}) {
		t.Error("Verify rejected a signature Sign just produced")
	}
	// An empty context is just an ordinary input here, not a distinct
	// scheme (unlike ed25519's SignCtx) — nil and []byte{} must be
	// equivalent.
	if !Verify(pub, testMsg, sig, nil) {
		t.Error("Verify treated a nil context differently from an empty one")
	}
}

func TestSignRejectsOversizeContext(t *testing.T) {
	priv := seckeyOne(t)
	if _, err := Sign(priv, testMsg, make([]byte, ContextMaxLen+1)); !errors.Is(err, ErrContextTooLong) {
		t.Errorf("Sign error = %v, want %v", err, ErrContextTooLong)
	}
}

func TestSignPhVerifyPhRoundTrip(t *testing.T) {
	priv := seckeyOne(t)
	pub := priv.PublicKey()
	context := []byte("example context")

	sig, err := SignPh(priv, testMsg, context)
	if err != nil {
		t.Fatalf("SignPh failed: %v", err)
	}
	if !VerifyPh(pub, testMsg, sig, context) {
		t.Error("VerifyPh rejected a signature SignPh just produced")
	}
}

func TestVerifyPhRejectsWrongMessageAndContext(t *testing.T) {
	priv := seckeyOne(t)
	pub := priv.PublicKey()
	context := []byte("example context")

	sig, err := SignPh(priv, testMsg, context)
	if err != nil {
		t.Fatalf("SignPh failed: %v", err)
	}
	if VerifyPh(pub, append(append([]byte{}, testMsg...), 0x00), sig, context) {
		t.Error("VerifyPh accepted a signature under a modified message")
	}
	if VerifyPh(pub, testMsg, sig, []byte("different context")) {
		t.Error("VerifyPh accepted a signature under the wrong context")
	}
}

func TestSignPhRejectsOversizeContext(t *testing.T) {
	priv := seckeyOne(t)
	if _, err := SignPh(priv, testMsg, make([]byte, ContextMaxLen+1)); !errors.Is(err, ErrContextTooLong) {
		t.Errorf("SignPh error = %v, want %v", err, ErrContextTooLong)
	}
}

func TestSignAndSignPhAreNotInterchangeable(t *testing.T) {
	priv := seckeyOne(t)
	pub := priv.PublicKey()

	sig, err := Sign(priv, testMsg, nil)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if VerifyPh(pub, testMsg, sig, nil) {
		t.Error("VerifyPh accepted a plain-Ed448 signature")
	}

	sigPh, err := SignPh(priv, testMsg, nil)
	if err != nil {
		t.Fatalf("SignPh failed: %v", err)
	}
	if Verify(pub, testMsg, sigPh, nil) {
		t.Error("Verify accepted an Ed448ph signature")
	}
}
