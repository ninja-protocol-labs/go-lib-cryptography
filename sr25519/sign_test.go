package sr25519

import (
	"bytes"
	"errors"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	priv := aliceKey(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	sig, err := Sign(priv, testCtx, testMsg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if !Verify(pub, testCtx, testMsg, sig) {
		t.Error("Verify rejected a signature Sign just produced")
	}
}

func TestSignVaries(t *testing.T) {
	priv := aliceKey(t)
	sig1, err := Sign(priv, testCtx, testMsg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	sig2, err := Sign(priv, testCtx, testMsg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	// schnorrkel draws a fresh random nonce per signature — unlike
	// secp256k1/ed25519/ed448's deterministic plain Sign, two signatures
	// over the same key and message must differ.
	if sig1.Bytes() == sig2.Bytes() {
		t.Error("Sign produced identical signatures on two separate calls")
	}
}

func TestVerifyRejectsWrongMessageKeyAndContext(t *testing.T) {
	priv := aliceKey(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	otherPriv := seckeyN(t, 2)
	otherPub, err := otherPriv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	sig, err := Sign(priv, testCtx, testMsg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if Verify(pub, testCtx, append(append([]byte{}, testMsg...), 0x00), sig) {
		t.Error("Verify accepted a signature under a modified message")
	}
	if Verify(otherPub, testCtx, testMsg, sig) {
		t.Error("Verify accepted a signature under the wrong public key")
	}
	if Verify(pub, []byte("different context"), testMsg, sig) {
		t.Error("Verify accepted a signature under the wrong context")
	}
}

func TestSignatureFromBytesRoundTrip(t *testing.T) {
	priv := aliceKey(t)
	sig, err := Sign(priv, testCtx, testMsg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	wire := sig.Bytes()
	parsed, err := SignatureFromBytes(wire[:])
	if err != nil {
		t.Fatalf("SignatureFromBytes failed: %v", err)
	}
	if parsed.Bytes() != wire {
		t.Error("SignatureFromBytes(sig.Bytes()) does not round trip")
	}
}

func TestSignatureFromBytesRejectsInvalid(t *testing.T) {
	cases := map[string][]byte{
		"empty": nil,
		"short": make([]byte, SignatureLen-1),
		"long":  make([]byte, SignatureLen+1),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := SignatureFromBytes(b); !errors.Is(err, ErrInvalidSignature) {
				t.Errorf("SignatureFromBytes(%s) error = %v, want %v", name, err, ErrInvalidSignature)
			}
		})
	}

	t.Run("missing schnorrkel marker bit", func(t *testing.T) {
		priv := aliceKey(t)
		sig, err := Sign(priv, testCtx, testMsg)
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		wire := sig.Bytes()
		wire[63] &^= 0x80 // clear the high bit that marks it as schnorrkel
		if _, err := SignatureFromBytes(wire[:]); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("SignatureFromBytes error = %v, want %v", err, ErrInvalidSignature)
		}
	})
}

func TestSignAndVerifyByteEquality(t *testing.T) {
	// Sanity check that Signature.Bytes() actually reflects what was
	// parsed/produced, not a stale zero value.
	priv := aliceKey(t)
	sig, err := Sign(priv, testCtx, testMsg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	wire := sig.Bytes()
	if bytes.Equal(wire[:], make([]byte, SignatureLen)) {
		t.Error("Sign produced an all-zero signature")
	}
}
