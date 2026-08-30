package x25519

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestECDHMatchesRFC7748Vector(t *testing.T) {
	alice, err := PrivateKeyFromBytes(alicePriv)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed: %v", err)
	}
	bob, err := PrivateKeyFromBytes(bobPriv)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed: %v", err)
	}
	alicePub, err := PublicKeyFromBytes(alicePub)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes failed: %v", err)
	}
	bobPub, err := PublicKeyFromBytes(bobPub)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes failed: %v", err)
	}

	sharedA, err := alice.ECDH(bobPub)
	if err != nil {
		t.Fatalf("ECDH failed: %v", err)
	}
	sharedB, err := bob.ECDH(alicePub)
	if err != nil {
		t.Fatalf("ECDH failed: %v", err)
	}

	if sharedA != sharedB {
		t.Error("alice.ECDH(bobPub) != bob.ECDH(alicePub)")
	}

	// This package's ECDH returns SHA-256 of the raw RFC 7748 result, not
	// the raw result itself (see dh.go) — so the expected value here is
	// SHA-256 of the RFC's own K, not K directly.
	want := sha256.Sum256(sharedSecretK)
	if sharedA != want {
		t.Errorf("ECDH result = %x, want SHA-256(K) = %x (RFC 7748 §6.1)", sharedA, want)
	}
}

func TestECDHDiffersForDifferentKeys(t *testing.T) {
	alice, err := PrivateKeyFromBytes(alicePriv)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed: %v", err)
	}
	bobPubKey, err := PublicKeyFromBytes(bobPub)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes failed: %v", err)
	}
	carol := seckeyN(t, 3)
	carolPub := carol.PublicKey()

	secretAB, err := alice.ECDH(bobPubKey)
	if err != nil {
		t.Fatalf("ECDH failed: %v", err)
	}
	secretAC, err := alice.ECDH(carolPub)
	if err != nil {
		t.Fatalf("ECDH failed: %v", err)
	}

	if bytes.Equal(secretAB[:], secretAC[:]) {
		t.Error("ECDH produced the same shared secret with two different peer keys")
	}
}

// TestECDHRejectsLowOrderPublicKey checks that a known low-order point
// (the all-zero u-coordinate) is rejected rather than silently producing
// a degenerate shared secret — the one failure mode PublicKeyFromBytes
// itself cannot catch (see the package doc).
func TestECDHRejectsLowOrderPublicKey(t *testing.T) {
	priv := seckeyN(t, 1)
	lowOrder, err := PublicKeyFromBytes(make([]byte, PubkeyLen))
	if err != nil {
		t.Fatalf("PublicKeyFromBytes failed: %v", err)
	}
	if _, err := priv.ECDH(lowOrder); !errors.Is(err, ErrECDHFailed) {
		t.Errorf("ECDH with the all-zero public key: error = %v, want %v", err, ErrECDHFailed)
	}
}
