package secp256k1

import (
	"bytes"
	"errors"
	"testing"
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

	if len(priv1.Bytes()) != 32 {
		t.Errorf("Bytes() length = %d, want 32", len(priv1.Bytes()))
	}
	if priv1.Equal(priv2) {
		t.Error("two calls to GeneratePrivateKey produced the same key")
	}
}

func TestPrivateKeyFromBytesRoundTrip(t *testing.T) {
	priv := seckeyOne(t)

	priv2, err := PrivateKeyFromBytes(priv.Bytes())
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
		{"curve order", mustDecodeHex(t, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")},
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
	priv1 := seckeyOne(t)
	priv2 := seckeyOne(t)

	other := make([]byte, 32)
	other[31] = 2
	priv3, err := PrivateKeyFromBytes(other)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed for a valid key: %v", err)
	}

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

func TestSeckeyOnePublicKey(t *testing.T) {
	priv := seckeyOne(t)

	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	if got := pub.Bytes(); !bytes.Equal(got, seckeyOnePubkeyCompressed) {
		t.Errorf("PublicKey().Bytes() = %x, want %x", got, seckeyOnePubkeyCompressed)
	}

	uncompressed, err := pub.BytesUncompressed()
	if err != nil {
		t.Fatalf("BytesUncompressed failed: %v", err)
	}
	if !bytes.Equal(uncompressed, seckeyOnePubkeyUncompressed) {
		t.Errorf("BytesUncompressed() = %x, want %x", uncompressed, seckeyOnePubkeyUncompressed)
	}
}

func TestPublicKeyFromBytesRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"from compressed", seckeyOnePubkeyCompressed},
		{"from uncompressed", seckeyOnePubkeyUncompressed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, err := PublicKeyFromBytes(tt.input)
			if err != nil {
				t.Fatalf("PublicKeyFromBytes failed for a valid key: %v", err)
			}
			if got := pub.Bytes(); !bytes.Equal(got, seckeyOnePubkeyCompressed) {
				t.Errorf("PublicKeyFromBytes(...).Bytes() = %x, want %x", got, seckeyOnePubkeyCompressed)
			}
		})
	}
}

func TestPublicKeyFromBytesRejectsInvalid(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", nil},
		{"truncated", []byte{0x02, 0x79, 0xbe}},
		{"bad prefix byte", append([]byte{0xff}, make([]byte, 32)...)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := PublicKeyFromBytes(tt.input); !errors.Is(err, ErrInvalidPublicKey) {
				t.Errorf("PublicKeyFromBytes() error = %v, want %v", err, ErrInvalidPublicKey)
			}
		})
	}
}

func TestPublicKeyEqual(t *testing.T) {
	pub1, err := seckeyOne(t).PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	pub2, err := seckeyOne(t).PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	other := make([]byte, 32)
	other[31] = 2
	otherPriv, err := PrivateKeyFromBytes(other)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed for a valid key: %v", err)
	}
	pub3, err := otherPriv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	if !pub1.Equal(pub2) {
		t.Error("two PublicKeys derived from the same PrivateKey are not Equal")
	}
	if pub1.Equal(pub3) {
		t.Error("two different PublicKeys are Equal")
	}
	if pub1.Equal(nil) {
		t.Error("PublicKey.Equal(nil) returned true")
	}
}

func TestBytesReturnsACopy(t *testing.T) {
	priv := seckeyOne(t)
	b := priv.Bytes()
	b[0] = 0xff
	if priv.Bytes()[0] == 0xff {
		t.Error("mutating the slice returned by Bytes() affected the PrivateKey")
	}

	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	pb := pub.Bytes()
	pb[0] = 0xff
	if pub.Bytes()[0] == 0xff {
		t.Error("mutating the slice returned by Bytes() affected the PublicKey")
	}
}
