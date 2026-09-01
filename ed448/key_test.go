package ed448

import (
	"errors"
	"testing"
)

func TestGeneratePrivateKey(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey failed: %v", err)
	}
	if priv.Bytes() == ([SeckeyLen]byte{}) {
		t.Error("GeneratePrivateKey returned an all-zero key")
	}
}

func TestPrivateKeyFromBytesRoundTrip(t *testing.T) {
	priv := seckeyOne(t)
	if got := priv.Bytes(); got != [SeckeyLen]byte(rfc8032Test1Seed) {
		t.Errorf("Bytes() = %x, want %x", got, rfc8032Test1Seed)
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
	priv1 := seckeyOne(t)
	priv1Again := seckeyOne(t)
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

func TestSeckeyOnePublicKey(t *testing.T) {
	priv := seckeyOne(t)
	pub := priv.PublicKey()
	if got := pub.Bytes(); got != [PubkeyLen]byte(rfc8032Test1Pubkey) {
		t.Errorf("PublicKey().Bytes() = %x, want %x (RFC 8032 §7.4 test 1)", got, rfc8032Test1Pubkey)
	}
}

func TestPublicKeyFromBytesRoundTrip(t *testing.T) {
	pub, err := PublicKeyFromBytes(rfc8032Test1Pubkey)
	if err != nil {
		t.Fatalf("PublicKeyFromBytes failed: %v", err)
	}
	if got := pub.Bytes(); got != [PubkeyLen]byte(rfc8032Test1Pubkey) {
		t.Errorf("Bytes() = %x, want %x", got, rfc8032Test1Pubkey)
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
	pub1 := seckeyOne(t).PublicKey()
	pub2 := seckeyN(t, 2).PublicKey()

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
	priv := seckeyOne(t)
	b := priv.Bytes()
	b[0] ^= 0xff
	if priv.Bytes() == b {
		t.Error("mutating the value from Bytes() affected the key")
	}

	pub := priv.PublicKey()
	pb := pub.Bytes()
	pb[0] ^= 0xff
	if pub.Bytes() == pb {
		t.Error("mutating the value from Bytes() affected the key")
	}
}
