package bls12377

import (
	"bytes"
	"testing"
)

func TestGeneratePrivateKey(t *testing.T) {
	a, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey failed: %v", err)
	}
	b, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey failed: %v", err)
	}
	if a.Equal(b) {
		t.Error("two generated private keys are identical")
	}
}

func TestPrivateKeyFromBytesRoundTrip(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey failed: %v", err)
	}
	privBytes := priv.Bytes()
	same, err := PrivateKeyFromBytes(privBytes[:])
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed: %v", err)
	}
	if !priv.Equal(same) {
		t.Error("PrivateKeyFromBytes(priv.Bytes()) != priv")
	}
}

func TestPrivateKeyFromBytesRejectsInvalid(t *testing.T) {
	// order is r itself; r and everything above it is out of range, as is
	// zero.
	atOrder := order.Bytes()

	tests := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"short", make([]byte, SeckeyLen-1)},
		{"long", make([]byte, SeckeyLen+1)},
		{"zero", make([]byte, SeckeyLen)},
		{"equal to the order", atOrder},
		{"all 0xff", bytes.Repeat([]byte{0xff}, SeckeyLen)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := PrivateKeyFromBytes(tt.in); err == nil {
				t.Error("PrivateKeyFromBytes accepted an invalid key")
			}
		})
	}
}

func TestPrivateKeyEqual(t *testing.T) {
	a := privKeyN(t, 1)
	b := privKeyN(t, 2)
	if !a.Equal(privKeyN(t, 1)) {
		t.Error("equal keys reported unequal")
	}
	if a.Equal(b) {
		t.Error("distinct keys reported equal")
	}
	if a.Equal(nil) {
		t.Error("PrivateKey.Equal(nil) is true")
	}
}

func TestPrivKeyOnePublicKeyMinPkIsTheGenerator(t *testing.T) {
	// 1*G = G, so the public key of the scalar 1 is the generator itself —
	// a known answer that needs no external test vector.
	pub := privKeyOne(t).PublicKeyMinPk()
	if pub.Bytes() != G1Generator().Bytes() {
		t.Error("PublicKeyMinPk of the scalar 1 is not the G1 generator")
	}
}

func TestPrivKeyOnePublicKeyMinSigIsTheGenerator(t *testing.T) {
	pub := privKeyOne(t).PublicKeyMinSig()
	if pub.Bytes() != G2Generator().Bytes() {
		t.Error("PublicKeyMinSig of the scalar 1 is not the G2 generator")
	}
}

func TestPublicKeyMinPkIsDeterministicAndUnique(t *testing.T) {
	a := privKeyN(t, 3)
	if !a.PublicKeyMinPk().Equal(a.PublicKeyMinPk()) {
		t.Error("PublicKeyMinPk is not deterministic")
	}
	if a.PublicKeyMinPk().Equal(privKeyN(t, 4).PublicKeyMinPk()) {
		t.Error("distinct private keys produced the same min-pk public key")
	}
}

func TestPublicKeyMinSigIsDeterministicAndUnique(t *testing.T) {
	a := privKeyN(t, 3)
	if !a.PublicKeyMinSig().Equal(a.PublicKeyMinSig()) {
		t.Error("PublicKeyMinSig is not deterministic")
	}
	if a.PublicKeyMinSig().Equal(privKeyN(t, 4).PublicKeyMinSig()) {
		t.Error("distinct private keys produced the same min-sig public key")
	}
}

func TestPublicKeyMinPkFromBytesRoundTrip(t *testing.T) {
	pub := privKeyN(t, 5).PublicKeyMinPk()
	b := pub.Bytes()
	same, err := PublicKeyMinPkFromBytes(b[:])
	if err != nil {
		t.Fatalf("PublicKeyMinPkFromBytes failed: %v", err)
	}
	if !pub.Equal(same) {
		t.Error("PublicKeyMinPkFromBytes(pub.Bytes()) != pub")
	}
}

func TestPublicKeyMinSigFromBytesRoundTrip(t *testing.T) {
	pub := privKeyN(t, 5).PublicKeyMinSig()
	b := pub.Bytes()
	same, err := PublicKeyMinSigFromBytes(b[:])
	if err != nil {
		t.Fatalf("PublicKeyMinSigFromBytes failed: %v", err)
	}
	if !pub.Equal(same) {
		t.Error("PublicKeyMinSigFromBytes(pub.Bytes()) != pub")
	}
}

func TestPublicKeyMinPkFromBytesRejectsInvalid(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"short", make([]byte, PubkeyMinPkLen-1)},
		{"long", make([]byte, PubkeyMinPkLen+1)},
		{"all 0xff", bytes.Repeat([]byte{0xff}, PubkeyMinPkLen)},
		// A correctly-sized, correctly-flagged encoding for x = 4, which
		// has no matching y: 4³+1 = 65 is a quadratic non-residue mod p.
		{"not on the curve", func() []byte {
			b := make([]byte, PubkeyMinPkLen)
			b[0] = 0x80 // compressed, smaller y
			b[PubkeyMinPkLen-1] = 4
			return b
		}()},
		// x = 0 gives y² = 1, so (0, 1) is a genuine curve point — of
		// order 3, well outside the prime-order subgroup. BLS12-377's G1
		// cofactor is ~3·10³⁷, so on-curve and in-subgroup are very
		// different conditions here, and this covers the second one.
		{"on the curve but outside the subgroup", func() []byte {
			b := make([]byte, PubkeyMinPkLen)
			b[0] = 0x80 // compressed, smaller y — x = 0, so y = 1
			return b
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := PublicKeyMinPkFromBytes(tt.in); err == nil {
				t.Error("PublicKeyMinPkFromBytes accepted an invalid key")
			}
		})
	}
}

func TestPublicKeyMinSigFromBytesRejectsInvalid(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"short", make([]byte, PubkeyMinSigLen-1)},
		{"long", make([]byte, PubkeyMinSigLen+1)},
		{"all 0xff", bytes.Repeat([]byte{0xff}, PubkeyMinSigLen)},
		// The min-pk public key's encoding is half the length, so it must
		// not be accepted here either.
		{"a G1 encoding", func() []byte {
			b := privKeyN(t, 6).PublicKeyMinPk().Bytes()
			return b[:]
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := PublicKeyMinSigFromBytes(tt.in); err == nil {
				t.Error("PublicKeyMinSigFromBytes accepted an invalid key")
			}
		})
	}
}

func TestPublicKeyEqualNil(t *testing.T) {
	if privKeyN(t, 7).PublicKeyMinPk().Equal(nil) {
		t.Error("PublicKeyMinPk.Equal(nil) is true")
	}
	if privKeyN(t, 7).PublicKeyMinSig().Equal(nil) {
		t.Error("PublicKeyMinSig.Equal(nil) is true")
	}
}
