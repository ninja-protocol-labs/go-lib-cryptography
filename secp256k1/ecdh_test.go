package secp256k1

import (
	"bytes"
	"testing"
)

func TestECDHSymmetric(t *testing.T) {
	privA := seckeyOne(t)
	pubA, err := privA.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	privB, err := PrivateKeyFromBytes(append(make([]byte, 31), 2))
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed: %v", err)
	}
	pubB, err := privB.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	// The actual Diffie-Hellman property: privA*pubB and privB*pubA are the
	// same point, so both sides must derive the same shared secret.
	secretAB, err := privA.ECDH(pubB)
	if err != nil {
		t.Fatalf("ECDH failed: %v", err)
	}
	secretBA, err := privB.ECDH(pubA)
	if err != nil {
		t.Fatalf("ECDH failed: %v", err)
	}

	if secretAB != secretBA {
		t.Error("privA.ECDH(pubB) != privB.ECDH(pubA)")
	}
}

func TestECDHDiffersForDifferentKeys(t *testing.T) {
	privA := seckeyOne(t)

	privB, err := PrivateKeyFromBytes(append(make([]byte, 31), 2))
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed: %v", err)
	}
	pubB, err := privB.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	privC, err := PrivateKeyFromBytes(append(make([]byte, 31), 3))
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed: %v", err)
	}
	pubC, err := privC.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	secretAB, err := privA.ECDH(pubB)
	if err != nil {
		t.Fatalf("ECDH failed: %v", err)
	}
	secretAC, err := privA.ECDH(pubC)
	if err != nil {
		t.Fatalf("ECDH failed: %v", err)
	}

	if bytes.Equal(secretAB[:], secretAC[:]) {
		t.Error("ECDH produced the same shared secret with two different peer keys")
	}
}
