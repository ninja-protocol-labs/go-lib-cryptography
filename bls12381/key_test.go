package bls12381

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ninja-protocol-labs/go-lib-cryptography/bls12381/internal"
)

func TestGeneratePrivateKey(t *testing.T) {
	priv1, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey failed: %v", err)
	}
	priv2, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey failed: %v", err)
	}

	if priv1.Equal(priv2) {
		t.Error("two calls to GeneratePrivateKey produced the same key")
	}
}

func TestPrivateKeyFromBytesRoundTrip(t *testing.T) {
	priv := privKeyOne(t)

	b := priv.Bytes()
	priv2, err := PrivateKeyFromBytes(b[:])
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed for a valid key: %v", err)
	}
	if !priv.Equal(priv2) {
		t.Error("PrivateKeyFromBytes(priv.Bytes()) != priv")
	}
}

func TestPrivateKeyFromBytesRejectsInvalid(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{"wrong length (short)", make([]byte, 31)},
		{"wrong length (long)", make([]byte, 33)},
		{"zero", make([]byte, 32)},
		{"all 0xff (exceeds the scalar field order)", bytes.Repeat([]byte{0xff}, 32)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := PrivateKeyFromBytes(tt.key); !errors.Is(err, ErrInvalidPrivateKey) {
				t.Errorf("PrivateKeyFromBytes() error = %v, want %v", err, ErrInvalidPrivateKey)
			}
		})
	}
}

func TestPrivateKeyEqual(t *testing.T) {
	priv1 := privKeyOne(t)
	priv2 := privKeyOne(t)
	priv3 := privKeyN(t, 2)

	if !priv1.Equal(priv2) {
		t.Error("two PrivateKeys parsed from the same bytes are not Equal")
	}
	if priv1.Equal(priv3) {
		t.Error("two different PrivateKeys are Equal")
	}
	if priv1.Equal(nil) {
		t.Error("PrivateKey.Equal(nil) returned true")
	}
}

func TestPrivKeyOnePublicKeyMinPkIsTheGenerator(t *testing.T) {
	// 1*G1 == G1 itself — a known-answer check against the internal
	// package's own already-verified generator, rather than a hardcoded
	// byte literal.
	priv := privKeyOne(t)
	g1 := internal.P1AffineGenerator()
	want := internal.P1AffineCompress(&g1)

	if got := priv.PublicKeyMinPk().Bytes(); got != want {
		t.Errorf("PublicKeyMinPk().Bytes() = %x, want %x", got, want)
	}
}

func TestPrivKeyOnePublicKeyMinSigIsTheGenerator(t *testing.T) {
	priv := privKeyOne(t)
	g2 := internal.P2AffineGenerator()
	want := internal.P2AffineCompress(&g2)

	if got := priv.PublicKeyMinSig().Bytes(); got != want {
		t.Errorf("PublicKeyMinSig().Bytes() = %x, want %x", got, want)
	}
}

func TestPublicKeyMinPkIsDeterministicAndUnique(t *testing.T) {
	privA := privKeyN(t, 3)
	privB := privKeyN(t, 4)

	pubA1 := privA.PublicKeyMinPk()
	pubA2 := privA.PublicKeyMinPk()
	if !pubA1.Equal(pubA2) {
		t.Error("PublicKeyMinPk is not deterministic for the same private key")
	}

	pubB := privB.PublicKeyMinPk()
	if pubA1.Equal(pubB) {
		t.Error("two different private keys produced Equal min-pk public keys")
	}
}

func TestPublicKeyMinSigIsDeterministicAndUnique(t *testing.T) {
	privA := privKeyN(t, 5)
	privB := privKeyN(t, 6)

	pubA1 := privA.PublicKeyMinSig()
	pubA2 := privA.PublicKeyMinSig()
	if !pubA1.Equal(pubA2) {
		t.Error("PublicKeyMinSig is not deterministic for the same private key")
	}

	pubB := privB.PublicKeyMinSig()
	if pubA1.Equal(pubB) {
		t.Error("two different private keys produced Equal min-sig public keys")
	}
}

func TestPublicKeyMinPkFromBytesRoundTrip(t *testing.T) {
	priv := privKeyN(t, 7)
	pub := priv.PublicKeyMinPk()

	b := pub.Bytes()
	parsed, err := PublicKeyMinPkFromBytes(b[:])
	if err != nil {
		t.Fatalf("PublicKeyMinPkFromBytes failed for a valid key: %v", err)
	}
	if !pub.Equal(parsed) {
		t.Error("PublicKeyMinPkFromBytes(pub.Bytes()) != pub")
	}
}

func TestPublicKeyMinPkFromBytesRejectsInvalid(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{"wrong length (short)", make([]byte, internal.P1CompressedLen-1)},
		{"wrong length (long)", make([]byte, internal.P1CompressedLen+1)},
		{"garbage", bytes.Repeat([]byte{0xff}, internal.P1CompressedLen)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := PublicKeyMinPkFromBytes(tt.key); !errors.Is(err, ErrInvalidPublicKey) {
				t.Errorf("PublicKeyMinPkFromBytes() error = %v, want %v", err, ErrInvalidPublicKey)
			}
		})
	}
}

func TestPublicKeyMinSigFromBytesRoundTrip(t *testing.T) {
	priv := privKeyN(t, 8)
	pub := priv.PublicKeyMinSig()

	b := pub.Bytes()
	parsed, err := PublicKeyMinSigFromBytes(b[:])
	if err != nil {
		t.Fatalf("PublicKeyMinSigFromBytes failed for a valid key: %v", err)
	}
	if !pub.Equal(parsed) {
		t.Error("PublicKeyMinSigFromBytes(pub.Bytes()) != pub")
	}
}

func TestPublicKeyMinSigFromBytesRejectsInvalid(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
	}{
		{"wrong length (short)", make([]byte, internal.P2CompressedLen-1)},
		{"wrong length (long)", make([]byte, internal.P2CompressedLen+1)},
		{"garbage", bytes.Repeat([]byte{0xff}, internal.P2CompressedLen)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := PublicKeyMinSigFromBytes(tt.key); !errors.Is(err, ErrInvalidPublicKey) {
				t.Errorf("PublicKeyMinSigFromBytes() error = %v, want %v", err, ErrInvalidPublicKey)
			}
		})
	}
}

func TestPublicKeyMinPkEqualNil(t *testing.T) {
	pub := privKeyOne(t).PublicKeyMinPk()
	if pub.Equal(nil) {
		t.Error("PublicKeyMinPk.Equal(nil) returned true")
	}
}

func TestPublicKeyMinSigEqualNil(t *testing.T) {
	pub := privKeyOne(t).PublicKeyMinSig()
	if pub.Equal(nil) {
		t.Error("PublicKeyMinSig.Equal(nil) returned true")
	}
}
