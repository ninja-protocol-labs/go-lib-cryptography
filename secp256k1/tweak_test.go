package secp256k1

import "testing"

func TestTweakAddMatchesBetweenPrivateAndPublic(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	var tweak [32]byte
	tweak[31] = 5

	tweakedPriv, err := priv.TweakAdd(tweak)
	if err != nil {
		t.Fatalf("PrivateKey.TweakAdd failed: %v", err)
	}
	tweakedPub, err := pub.TweakAdd(tweak)
	if err != nil {
		t.Fatalf("PublicKey.TweakAdd failed: %v", err)
	}

	wantPub, err := tweakedPriv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	if !tweakedPub.Equal(wantPub) {
		t.Error("pub.TweakAdd(t) != pubkey(priv.TweakAdd(t))")
	}
}

func TestTweakMulMatchesBetweenPrivateAndPublic(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	var tweak [32]byte
	tweak[31] = 5

	tweakedPriv, err := priv.TweakMul(tweak)
	if err != nil {
		t.Fatalf("PrivateKey.TweakMul failed: %v", err)
	}
	tweakedPub, err := pub.TweakMul(tweak)
	if err != nil {
		t.Fatalf("PublicKey.TweakMul failed: %v", err)
	}

	wantPub, err := tweakedPriv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	if !tweakedPub.Equal(wantPub) {
		t.Error("pub.TweakMul(t) != pubkey(priv.TweakMul(t))")
	}
}

func TestNegateMatchesBetweenPrivateAndPublic(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	negPriv, err := priv.Negate()
	if err != nil {
		t.Fatalf("PrivateKey.Negate failed: %v", err)
	}
	negPub, err := pub.Negate()
	if err != nil {
		t.Fatalf("PublicKey.Negate failed: %v", err)
	}

	wantPub, err := negPriv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	if !negPub.Equal(wantPub) {
		t.Error("pub.Negate() != pubkey(priv.Negate())")
	}
	if negPriv.Equal(priv) {
		t.Error("Negate() returned an unchanged key")
	}
}

func TestNegateTwiceReturnsOriginal(t *testing.T) {
	priv := seckeyOne(t)

	negOnce, err := priv.Negate()
	if err != nil {
		t.Fatalf("Negate failed: %v", err)
	}
	negTwice, err := negOnce.Negate()
	if err != nil {
		t.Fatalf("Negate failed: %v", err)
	}

	if !negTwice.Equal(priv) {
		t.Error("negating a key twice did not reproduce the original")
	}
}

func TestTweakAndNegateDoNotMutateReceiver(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	var tweak [32]byte
	tweak[31] = 5

	if _, err := priv.TweakAdd(tweak); err != nil {
		t.Fatalf("TweakAdd failed: %v", err)
	}
	if _, err := pub.TweakAdd(tweak); err != nil {
		t.Fatalf("TweakAdd failed: %v", err)
	}
	if !priv.Equal(seckeyOne(t)) {
		t.Error("PrivateKey.TweakAdd mutated the receiver")
	}
	origPub, err := seckeyOne(t).PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	if !pub.Equal(origPub) {
		t.Error("PublicKey.TweakAdd mutated the receiver")
	}
}
