package bls12377

import (
	"bytes"
	"hash"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
)

// eddsaHash is the Fiat-Shamir hash these tests sign under: MiMC over 𝔽r,
// the one gnark's own circuits use. Sign and Verify each need their own
// instance's state reset, so this returns a fresh one per call.
func eddsaHash() hash.Hash {
	return mimc.NewMiMC()
}

// eddsaMsg is a single 𝔽r element. gnark's EdDSA signs a sequence of field
// elements, and MiMC absorbs exactly 32 bytes at a time, so the message has
// to be a whole number of 32-byte, in-range chunks — not arbitrary bytes.
var eddsaMsg = func() []byte {
	m := make([]byte, SeckeyLen)
	copy(m[1:], "the quick brown fox")
	return m
}()

// eddsaKeyFromSeed returns the EdDSA key pair for the seed byte n repeated.
func eddsaKeyFromSeed(t *testing.T, n byte) *EdDSAPrivateKey {
	t.Helper()
	priv, err := EdDSAPrivateKeyFromSeed(bytes.Repeat([]byte{n}, EdDSASeedLen))
	if err != nil {
		t.Fatalf("EdDSAPrivateKeyFromSeed failed: %v", err)
	}
	return priv
}

func TestGenerateEdDSAPrivateKey(t *testing.T) {
	a, err := GenerateEdDSAPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEdDSAPrivateKey failed: %v", err)
	}
	b, err := GenerateEdDSAPrivateKey()
	if err != nil {
		t.Fatalf("GenerateEdDSAPrivateKey failed: %v", err)
	}
	if a.Equal(b) {
		t.Error("two generated EdDSA private keys are identical")
	}
	if a.Equal(nil) {
		t.Error("EdDSAPrivateKey.Equal(nil) is true")
	}
}

func TestEdDSAPrivateKeyFromSeedIsDeterministic(t *testing.T) {
	a := eddsaKeyFromSeed(t, 1)
	b := eddsaKeyFromSeed(t, 1)
	if !a.Equal(b) {
		t.Error("the same seed produced two different keys")
	}
	if a.Equal(eddsaKeyFromSeed(t, 2)) {
		t.Error("two different seeds produced the same key")
	}
	if _, err := EdDSAPrivateKeyFromSeed(make([]byte, EdDSASeedLen-1)); err == nil {
		t.Error("EdDSAPrivateKeyFromSeed accepted a short seed")
	}
}

func TestEdDSAPrivateKeyFromBytesRoundTrip(t *testing.T) {
	priv := eddsaKeyFromSeed(t, 3)
	b := priv.Bytes()
	same, err := EdDSAPrivateKeyFromBytes(b[:])
	if err != nil {
		t.Fatalf("EdDSAPrivateKeyFromBytes failed: %v", err)
	}
	if !priv.Equal(same) {
		t.Error("EdDSAPrivateKeyFromBytes(priv.Bytes()) != priv")
	}
	if !priv.PublicKey().Equal(same.PublicKey()) {
		t.Error("the round-tripped key derives a different public key")
	}
	if _, err := EdDSAPrivateKeyFromBytes(nil); err == nil {
		t.Error("EdDSAPrivateKeyFromBytes accepted an empty input")
	}
	if _, err := EdDSAPrivateKeyFromBytes(make([]byte, EdDSAPrivkeyLen)); err == nil {
		t.Error("EdDSAPrivateKeyFromBytes accepted an all-zero key")
	}
}

func TestEdDSAPublicKeyFromBytesRoundTrip(t *testing.T) {
	pub := eddsaKeyFromSeed(t, 4).PublicKey()
	b := pub.Bytes()
	same, err := EdDSAPublicKeyFromBytes(b[:])
	if err != nil {
		t.Fatalf("EdDSAPublicKeyFromBytes failed: %v", err)
	}
	if !pub.Equal(same) {
		t.Error("EdDSAPublicKeyFromBytes(pub.Bytes()) != pub")
	}
	if pub.Equal(nil) {
		t.Error("EdDSAPublicKey.Equal(nil) is true")
	}
	if _, err := EdDSAPublicKeyFromBytes(nil); err == nil {
		t.Error("EdDSAPublicKeyFromBytes accepted an empty input")
	}
	// 0x01 repeated decodes to a point outside the prime-order subgroup.
	// (All-0xff, which serves as the garbage vector in bn254's mirror of
	// this test, happens to be a *valid* point on this curve — a reminder
	// that "obviously invalid bytes" is curve-specific.)
	if _, err := EdDSAPublicKeyFromBytes(bytes.Repeat([]byte{0x01}, EdDSAPubkeyLen)); err == nil {
		t.Error("EdDSAPublicKeyFromBytes accepted a point outside the subgroup")
	}
}

func TestSignVerifyEdDSARoundTrip(t *testing.T) {
	priv := eddsaKeyFromSeed(t, 5)
	sig, err := SignEdDSA(priv, eddsaMsg, eddsaHash())
	if err != nil {
		t.Fatalf("SignEdDSA failed: %v", err)
	}
	if !VerifyEdDSA(priv.PublicKey(), eddsaMsg, sig[:], eddsaHash()) {
		t.Error("VerifyEdDSA rejected a genuine signature")
	}
}

func TestSignEdDSAIsDeterministic(t *testing.T) {
	// The nonce comes from BLAKE2b(nonce source ∥ message) with no fresh
	// entropy, so signing is deterministic — unlike SignECDSA above.
	priv := eddsaKeyFromSeed(t, 6)
	a, err := SignEdDSA(priv, eddsaMsg, eddsaHash())
	if err != nil {
		t.Fatalf("SignEdDSA failed: %v", err)
	}
	b, err := SignEdDSA(priv, eddsaMsg, eddsaHash())
	if err != nil {
		t.Fatalf("SignEdDSA failed: %v", err)
	}
	if a != b {
		t.Error("SignEdDSA is not deterministic")
	}
}

func TestVerifyEdDSARejectsWrongInputs(t *testing.T) {
	priv := eddsaKeyFromSeed(t, 7)
	pub := priv.PublicKey()
	sig, err := SignEdDSA(priv, eddsaMsg, eddsaHash())
	if err != nil {
		t.Fatalf("SignEdDSA failed: %v", err)
	}

	otherMsg := make([]byte, SeckeyLen)
	otherMsg[SeckeyLen-1] = 0x2a

	if VerifyEdDSA(pub, otherMsg, sig[:], eddsaHash()) {
		t.Error("VerifyEdDSA accepted the wrong message")
	}
	if VerifyEdDSA(eddsaKeyFromSeed(t, 8).PublicKey(), eddsaMsg, sig[:], eddsaHash()) {
		t.Error("VerifyEdDSA accepted the wrong public key")
	}
	if VerifyEdDSA(nil, eddsaMsg, sig[:], eddsaHash()) {
		t.Error("VerifyEdDSA accepted a nil public key")
	}
	if VerifyEdDSA(pub, eddsaMsg, sig[:len(sig)-1], eddsaHash()) {
		t.Error("VerifyEdDSA accepted a truncated signature")
	}

	tampered := sig
	tampered[len(tampered)-1] ^= 0x01
	if VerifyEdDSA(pub, eddsaMsg, tampered[:], eddsaHash()) {
		t.Error("VerifyEdDSA accepted a tampered signature")
	}
}

func TestEdDSARequiresAHash(t *testing.T) {
	// Unlike RFC 8032's Ed25519 there is no built-in message hash, so the
	// Fiat-Shamir hash is not optional.
	priv := eddsaKeyFromSeed(t, 9)
	if _, err := SignEdDSA(priv, eddsaMsg, nil); err == nil {
		t.Error("SignEdDSA accepted a nil hash")
	}
	sig, err := SignEdDSA(priv, eddsaMsg, eddsaHash())
	if err != nil {
		t.Fatalf("SignEdDSA failed: %v", err)
	}
	if VerifyEdDSA(priv.PublicKey(), eddsaMsg, sig[:], nil) {
		t.Error("VerifyEdDSA accepted a nil hash")
	}
}

func TestSignEdDSARejectsNilKey(t *testing.T) {
	if _, err := SignEdDSA(nil, eddsaMsg, eddsaHash()); err == nil {
		t.Error("SignEdDSA accepted a nil private key")
	}
}
