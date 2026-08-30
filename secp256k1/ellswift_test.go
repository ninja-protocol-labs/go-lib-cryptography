package secp256k1

import "testing"

func TestEllswiftEncodeDecodeRoundTrip(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	var rnd [32]byte
	rnd[0] = 0x01
	ell, err := pub.EllswiftEncode(rnd)
	if err != nil {
		t.Fatalf("EllswiftEncode failed: %v", err)
	}

	decoded := EllswiftDecode(ell)
	if !decoded.Equal(pub) {
		t.Error("EllswiftDecode(pub.EllswiftEncode(rnd)) != pub")
	}
}

func TestPrivateKeyEllswiftEncodeMatchesPublicKey(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	ell, err := priv.EllswiftEncode(nil)
	if err != nil {
		t.Fatalf("PrivateKey.EllswiftEncode failed: %v", err)
	}

	// PrivateKey.EllswiftEncode is documented as equivalent to deriving the
	// pubkey and then encoding it, modulo the encoding's inherent
	// randomization — so the only thing checkable without reimplementing
	// the encoder is that it decodes back to the same point.
	decoded := EllswiftDecode(ell)
	if !decoded.Equal(pub) {
		t.Error("EllswiftDecode(priv.EllswiftEncode(nil)) != priv.PublicKey()")
	}
}

func TestEllswiftEncodeVariesWithRnd(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	var rnd1, rnd2 [32]byte
	rnd1[0] = 0x01
	rnd2[0] = 0x02

	ell1, err := pub.EllswiftEncode(rnd1)
	if err != nil {
		t.Fatalf("EllswiftEncode failed: %v", err)
	}
	ell2, err := pub.EllswiftEncode(rnd2)
	if err != nil {
		t.Fatalf("EllswiftEncode failed: %v", err)
	}

	if ell1 == ell2 {
		t.Error("EllswiftEncode produced identical output for different rnd")
	}
	if !EllswiftDecode(ell1).Equal(pub) || !EllswiftDecode(ell2).Equal(pub) {
		t.Error("both encodings must still decode back to the same point")
	}
}

func TestEllswiftECDHSymmetric(t *testing.T) {
	privA := seckeyOne(t)
	privB, err := PrivateKeyFromBytes(append(make([]byte, 31), 2))
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed: %v", err)
	}

	ellA, err := privA.EllswiftEncode(nil)
	if err != nil {
		t.Fatalf("EllswiftEncode failed: %v", err)
	}
	ellB, err := privB.EllswiftEncode(nil)
	if err != nil {
		t.Fatalf("EllswiftEncode failed: %v", err)
	}

	secretA, err := privA.EllswiftECDH(ellA, ellB, false)
	if err != nil {
		t.Fatalf("EllswiftECDH failed: %v", err)
	}
	secretB, err := privB.EllswiftECDH(ellA, ellB, true)
	if err != nil {
		t.Fatalf("EllswiftECDH failed: %v", err)
	}

	if secretA != secretB {
		t.Error("privA.EllswiftECDH(..., isPartyB=false) != privB.EllswiftECDH(..., isPartyB=true)")
	}
}
