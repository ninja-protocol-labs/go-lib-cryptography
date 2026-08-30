package sr25519

import (
	"bytes"
	"errors"
	"testing"
)

func TestGeneratePrivateKey(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey failed: %v", err)
	}
	if len(priv.Bytes()) != SeckeyLen {
		t.Errorf("Bytes() length = %d, want %d", len(priv.Bytes()), SeckeyLen)
	}
}

func TestPrivateKeyFromBytesRoundTrip(t *testing.T) {
	priv := aliceKey(t)
	if !bytes.Equal(priv.Bytes(), aliceScalar) {
		t.Errorf("Bytes() = %x, want %x", priv.Bytes(), aliceScalar)
	}
}

func TestPrivateKeyFromBytesRejectsInvalidLength(t *testing.T) {
	cases := map[string][]byte{
		"empty": nil,
		"short": make([]byte, SeckeyLen-1),
		"long":  make([]byte, SeckeyLen+1),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := PrivateKeyFromBytes(b); !errors.Is(err, ErrInvalidPrivateKey) {
				t.Errorf("PrivateKeyFromBytes(%s) error = %v, want %v", name, err, ErrInvalidPrivateKey)
			}
		})
	}
}

func TestPrivateKeyFromBytesRejectsZero(t *testing.T) {
	if _, err := PrivateKeyFromBytes(make([]byte, SeckeyLen)); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Errorf("PrivateKeyFromBytes(zero) error = %v, want %v", err, ErrInvalidPrivateKey)
	}
}

func TestPrivateKeyFromBytesRejectsOutOfRangeScalar(t *testing.T) {
	// All-0xff is far larger than Ristretto255's ~2^252 group order —
	// not a canonically-encoded scalar at all.
	garbage := make([]byte, SeckeyLen)
	for i := range garbage {
		garbage[i] = 0xff
	}
	if _, err := PrivateKeyFromBytes(garbage); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Errorf("PrivateKeyFromBytes(garbage) error = %v, want %v", err, ErrInvalidPrivateKey)
	}
}

func TestPrivateKeyEqual(t *testing.T) {
	priv1 := aliceKey(t)
	priv1Again := aliceKey(t)
	priv2 := seckeyN(t, 2)

	if !priv1.Equal(priv1Again) {
		t.Error("Equal returned false for two keys built from the same seed")
	}
	if priv1.Equal(priv2) {
		t.Error("Equal returned true for two different keys")
	}
	if priv1.Equal(nil) {
		t.Error("Equal returned true against nil")
	}
}

func TestAlicePublicKey(t *testing.T) {
	priv := aliceKey(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	if !bytes.Equal(pub.Bytes(), alicePubkey) {
		t.Errorf("PublicKey().Bytes() = %x, want %x (Substrate //Alice dev seed)", pub.Bytes(), alicePubkey)
	}
}

func TestPublicKeyFromBytesRoundTrip(t *testing.T) {
	pub, err := PublicKeyFromBytes(alicePubkey)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes failed: %v", err)
	}
	if !bytes.Equal(pub.Bytes(), alicePubkey) {
		t.Errorf("Bytes() = %x, want %x", pub.Bytes(), alicePubkey)
	}
}

func TestPublicKeyFromBytesRejectsInvalidLength(t *testing.T) {
	cases := map[string][]byte{
		"empty": nil,
		"short": make([]byte, PubkeyLen-1),
		"long":  make([]byte, PubkeyLen+1),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := PublicKeyFromBytes(b); !errors.Is(err, ErrInvalidPublicKey) {
				t.Errorf("PublicKeyFromBytes(%s) error = %v, want %v", name, err, ErrInvalidPublicKey)
			}
		})
	}
}

func TestPublicKeyFromBytesRejectsNonCanonicalEncoding(t *testing.T) {
	// All-0xff is the correct length but does not decode to a valid
	// Ristretto point — real validation, unlike ed25519/ed448's
	// length-only checks (see the package doc).
	garbage := make([]byte, PubkeyLen)
	for i := range garbage {
		garbage[i] = 0xff
	}
	if _, err := PublicKeyFromBytes(garbage); !errors.Is(err, ErrInvalidPublicKey) {
		t.Errorf("PublicKeyFromBytes(garbage) error = %v, want %v", err, ErrInvalidPublicKey)
	}
}

func TestPublicKeyEqual(t *testing.T) {
	pub1, err := PublicKeyFromBytes(alicePubkey)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes failed: %v", err)
	}
	priv2 := seckeyN(t, 2)
	pub2, err := priv2.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	if !pub1.Equal(pub1) {
		t.Error("Equal returned false comparing a key to itself")
	}
	if pub1.Equal(pub2) {
		t.Error("Equal returned true for two different keys")
	}
	if pub1.Equal(nil) {
		t.Error("Equal returned true against nil")
	}
}

func TestBytesReturnsACopy(t *testing.T) {
	priv := aliceKey(t)
	b := priv.Bytes()
	b[0] ^= 0xff
	if bytes.Equal(priv.Bytes(), b) {
		t.Error("mutating the slice from Bytes() affected the key")
	}

	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	pb := pub.Bytes()
	pb[0] ^= 0xff
	if bytes.Equal(pub.Bytes(), pb) {
		t.Error("mutating the slice from Bytes() affected the key")
	}
}
