package x25519

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
	priv, err := PrivateKeyFromBytes(alicePriv)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed: %v", err)
	}
	if !bytes.Equal(priv.Bytes(), alicePriv) {
		t.Errorf("Bytes() = %x, want %x", priv.Bytes(), alicePriv)
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

func TestPrivateKeyEqual(t *testing.T) {
	priv1, err := PrivateKeyFromBytes(alicePriv)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed: %v", err)
	}
	priv1Again, err := PrivateKeyFromBytes(alicePriv)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed: %v", err)
	}
	priv2 := seckeyN(t, 2)

	if !priv1.Equal(priv1Again) {
		t.Error("Equal returned false for two keys built from the same bytes")
	}
	if priv1.Equal(priv2) {
		t.Error("Equal returned true for two different keys")
	}
	if priv1.Equal(nil) {
		t.Error("Equal returned true against nil")
	}
}

func TestAlicePublicKeyMatchesRFC7748(t *testing.T) {
	priv, err := PrivateKeyFromBytes(alicePriv)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed: %v", err)
	}
	pub := priv.PublicKey()
	if !bytes.Equal(pub.Bytes(), alicePub) {
		t.Errorf("PublicKey().Bytes() = %x, want %x (RFC 7748 §6.1)", pub.Bytes(), alicePub)
	}
}

func TestPublicKeyFromBytesRoundTrip(t *testing.T) {
	pub, err := PublicKeyFromBytes(alicePub)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes failed: %v", err)
	}
	if !bytes.Equal(pub.Bytes(), alicePub) {
		t.Errorf("Bytes() = %x, want %x", pub.Bytes(), alicePub)
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

func TestPublicKeyEqual(t *testing.T) {
	pub1, err := PublicKeyFromBytes(alicePub)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes failed: %v", err)
	}
	pub2, err := PublicKeyFromBytes(bobPub)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes failed: %v", err)
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
	priv, err := PrivateKeyFromBytes(alicePriv)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed: %v", err)
	}
	b := priv.Bytes()
	b[0] ^= 0xff
	if bytes.Equal(priv.Bytes(), b) {
		t.Error("mutating the slice from Bytes() affected the key")
	}

	pub := priv.PublicKey()
	pb := pub.Bytes()
	pb[0] ^= 0xff
	if bytes.Equal(pub.Bytes(), pb) {
		t.Error("mutating the slice from Bytes() affected the key")
	}
}
