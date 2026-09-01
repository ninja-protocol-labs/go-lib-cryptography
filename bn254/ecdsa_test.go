package bn254

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// ecdsaKeyN returns the ECDSA private key for the small scalar n.
func ecdsaKeyN(t *testing.T, n byte) *ECDSAPrivateKey {
	t.Helper()
	scalar := scalarN(n)
	priv, err := ECDSAPrivateKeyFromBytes(scalar[:])
	if err != nil {
		t.Fatalf("ECDSAPrivateKeyFromBytes failed for a valid key: %v", err)
	}
	return priv
}

func TestGenerateECDSAPrivateKey(t *testing.T) {
	a, err := GenerateECDSAPrivateKey()
	if err != nil {
		t.Fatalf("GenerateECDSAPrivateKey failed: %v", err)
	}
	b, err := GenerateECDSAPrivateKey()
	if err != nil {
		t.Fatalf("GenerateECDSAPrivateKey failed: %v", err)
	}
	if a.Equal(b) {
		t.Error("two generated ECDSA private keys are identical")
	}
}

func TestECDSAPrivateKeyFromBytesRoundTrip(t *testing.T) {
	priv, err := GenerateECDSAPrivateKey()
	if err != nil {
		t.Fatalf("GenerateECDSAPrivateKey failed: %v", err)
	}
	privBytes := priv.Bytes()
	same, err := ECDSAPrivateKeyFromBytes(privBytes[:])
	if err != nil {
		t.Fatalf("ECDSAPrivateKeyFromBytes failed: %v", err)
	}
	if !priv.Equal(same) {
		t.Error("ECDSAPrivateKeyFromBytes(priv.Bytes()) != priv")
	}
	if !priv.PublicKey().Equal(same.PublicKey()) {
		t.Error("the round-tripped key derives a different public key")
	}
	if priv.Equal(nil) {
		t.Error("ECDSAPrivateKey.Equal(nil) is true")
	}
}

func TestECDSAPrivateKeyDerivesThePublicKeyItself(t *testing.T) {
	// The scalar 1 must derive the G1 generator, the same as the BLS
	// PrivateKey does — proof that this parser recomputes the public half
	// rather than trusting a supplied one.
	priv := ecdsaKeyN(t, 1)
	if priv.PublicKey().Bytes() != G1Generator().Bytes() {
		t.Error("the ECDSA public key of the scalar 1 is not the G1 generator")
	}
}

func TestECDSAPrivateKeyFromBytesRejectsInvalid(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"short", make([]byte, SeckeyLen-1)},
		{"long", make([]byte, SeckeyLen+1)},
		{"zero", make([]byte, SeckeyLen)},
		{"equal to the order", order.Bytes()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ECDSAPrivateKeyFromBytes(tt.in); err == nil {
				t.Error("ECDSAPrivateKeyFromBytes accepted an invalid key")
			}
		})
	}
}

func TestECDSAPublicKeyFromBytesRoundTrip(t *testing.T) {
	pub := ecdsaKeyN(t, 2).PublicKey()
	pubBytes := pub.Bytes()
	same, err := ECDSAPublicKeyFromBytes(pubBytes[:])
	if err != nil {
		t.Fatalf("ECDSAPublicKeyFromBytes failed: %v", err)
	}
	if !pub.Equal(same) {
		t.Error("ECDSAPublicKeyFromBytes(pub.Bytes()) != pub")
	}
	if pub.Equal(nil) {
		t.Error("ECDSAPublicKey.Equal(nil) is true")
	}
	if _, err := ECDSAPublicKeyFromBytes(bytes.Repeat([]byte{0xff}, ECDSAPubkeyLen)); err == nil {
		t.Error("ECDSAPublicKeyFromBytes accepted garbage")
	}
	if _, err := ECDSAPublicKeyFromBytes(nil); err == nil {
		t.Error("ECDSAPublicKeyFromBytes accepted an empty input")
	}
}

func TestSignVerifyECDSARoundTrip(t *testing.T) {
	priv := ecdsaKeyN(t, 3)
	sig, err := SignECDSA(priv, testMsg, sha256.New())
	if err != nil {
		t.Fatalf("SignECDSA failed: %v", err)
	}
	if !VerifyECDSA(priv.PublicKey(), testMsg, sig[:], sha256.New()) {
		t.Error("VerifyECDSA rejected a genuine signature")
	}
}

func TestSignECDSAVariesPerCall(t *testing.T) {
	// The nonce is hedged with fresh entropy, so signing the same message
	// twice gives different bytes — both of which must verify.
	priv := ecdsaKeyN(t, 4)
	a, err := SignECDSA(priv, testMsg, sha256.New())
	if err != nil {
		t.Fatalf("SignECDSA failed: %v", err)
	}
	b, err := SignECDSA(priv, testMsg, sha256.New())
	if err != nil {
		t.Fatalf("SignECDSA failed: %v", err)
	}
	if a == b {
		t.Error("two signatures over the same message are identical; the nonce is not hedged")
	}
	if !VerifyECDSA(priv.PublicKey(), testMsg, a[:], sha256.New()) ||
		!VerifyECDSA(priv.PublicKey(), testMsg, b[:], sha256.New()) {
		t.Error("VerifyECDSA rejected one of two genuine signatures")
	}
}

func TestSignECDSAPreHashed(t *testing.T) {
	// hFunc == nil means "the message is already a digest".
	priv := ecdsaKeyN(t, 5)
	digest := sha256.Sum256(testMsg)

	sig, err := SignECDSA(priv, digest[:], nil)
	if err != nil {
		t.Fatalf("SignECDSA failed: %v", err)
	}
	if !VerifyECDSA(priv.PublicKey(), digest[:], sig[:], nil) {
		t.Error("VerifyECDSA rejected a genuine pre-hashed signature")
	}
	// The two paths sign the same digest, so a signature from either
	// verifies under the other — even though the signatures themselves
	// differ, both because the nonce is hedged and because it is derived
	// from the raw input rather than the digest.
	hashed, err := SignECDSA(priv, testMsg, sha256.New())
	if err != nil {
		t.Fatalf("SignECDSA failed: %v", err)
	}
	if !VerifyECDSA(priv.PublicKey(), digest[:], hashed[:], nil) {
		t.Error("a signature made over the message did not verify against its digest")
	}
}

func TestVerifyECDSARejectsWrongInputs(t *testing.T) {
	priv := ecdsaKeyN(t, 6)
	pub := priv.PublicKey()
	sig, err := SignECDSA(priv, testMsg, sha256.New())
	if err != nil {
		t.Fatalf("SignECDSA failed: %v", err)
	}

	if VerifyECDSA(pub, []byte("a different message"), sig[:], sha256.New()) {
		t.Error("VerifyECDSA accepted the wrong message")
	}
	if VerifyECDSA(ecdsaKeyN(t, 7).PublicKey(), testMsg, sig[:], sha256.New()) {
		t.Error("VerifyECDSA accepted the wrong public key")
	}
	if VerifyECDSA(pub, testMsg, sig[:], nil) {
		t.Error("VerifyECDSA accepted a signature checked against the unhashed message")
	}
	if VerifyECDSA(nil, testMsg, sig[:], sha256.New()) {
		t.Error("VerifyECDSA accepted a nil public key")
	}
	if VerifyECDSA(pub, testMsg, sig[:len(sig)-1], sha256.New()) {
		t.Error("VerifyECDSA accepted a truncated signature")
	}

	tampered := sig
	tampered[len(tampered)-1] ^= 0x01
	if VerifyECDSA(pub, testMsg, tampered[:], sha256.New()) {
		t.Error("VerifyECDSA accepted a tampered signature")
	}
}

func TestSignECDSARejectsNilKey(t *testing.T) {
	if _, err := SignECDSA(nil, testMsg, sha256.New()); err == nil {
		t.Error("SignECDSA accepted a nil private key")
	}
}
