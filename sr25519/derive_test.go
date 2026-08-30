package sr25519

import "testing"

func TestDeriveHardProducesUsableKey(t *testing.T) {
	priv := aliceKey(t)
	var chainCode [ChainCodeLen]byte
	chainCode[0] = 1

	child, newCC, err := priv.DeriveHard(chainCode, []byte("index"))
	if err != nil {
		t.Fatalf("DeriveHard failed: %v", err)
	}
	if child.Equal(priv) {
		t.Error("DeriveHard produced a child identical to the parent")
	}

	childPub, err := child.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	sig, err := Sign(child, testCtx, testMsg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if !Verify(childPub, testCtx, testMsg, sig) {
		t.Error("a signature from a hard-derived key failed to verify under its own derived public key")
	}

	// Deriving again with the (possibly different) resulting chain code
	// must still work — it's just another valid chain code.
	if _, _, err := child.DeriveHard(newCC, []byte("index-2")); err != nil {
		t.Errorf("DeriveHard on a derived key failed: %v", err)
	}
}

func TestDeriveHardIsDeterministic(t *testing.T) {
	priv := aliceKey(t)
	var chainCode [ChainCodeLen]byte
	chainCode[0] = 1

	child1, cc1, err := priv.DeriveHard(chainCode, []byte("index"))
	if err != nil {
		t.Fatalf("DeriveHard failed: %v", err)
	}
	child2, cc2, err := priv.DeriveHard(chainCode, []byte("index"))
	if err != nil {
		t.Fatalf("DeriveHard failed: %v", err)
	}

	if !child1.Equal(child2) {
		t.Error("DeriveHard with the same chain code and index produced two different keys")
	}
	if cc1 != cc2 {
		t.Error("DeriveHard with the same chain code and index produced two different resulting chain codes")
	}
}

func TestDeriveHardDiffersByIndex(t *testing.T) {
	priv := aliceKey(t)
	var chainCode [ChainCodeLen]byte

	child1, _, err := priv.DeriveHard(chainCode, []byte("index-1"))
	if err != nil {
		t.Fatalf("DeriveHard failed: %v", err)
	}
	child2, _, err := priv.DeriveHard(chainCode, []byte("index-2"))
	if err != nil {
		t.Fatalf("DeriveHard failed: %v", err)
	}

	if child1.Equal(child2) {
		t.Error("DeriveHard produced the same child for two different indices")
	}
}

func TestDeriveSoftIsDeterministic(t *testing.T) {
	priv := aliceKey(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	var chainCode [ChainCodeLen]byte
	chainCode[0] = 7

	childPub1, cc1, err := pub.DeriveSoft(chainCode, []byte("index"))
	if err != nil {
		t.Fatalf("DeriveSoft failed: %v", err)
	}
	childPub2, cc2, err := pub.DeriveSoft(chainCode, []byte("index"))
	if err != nil {
		t.Fatalf("DeriveSoft failed: %v", err)
	}

	if !childPub1.Equal(childPub2) {
		t.Error("DeriveSoft with the same chain code and index produced two different public keys")
	}
	if cc1 != cc2 {
		t.Error("DeriveSoft with the same chain code and index produced two different resulting chain codes")
	}
}

func TestDeriveSoftDiffersByIndex(t *testing.T) {
	priv := aliceKey(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	var chainCode [ChainCodeLen]byte

	child1, _, err := pub.DeriveSoft(chainCode, []byte("index-1"))
	if err != nil {
		t.Fatalf("DeriveSoft failed: %v", err)
	}
	child2, _, err := pub.DeriveSoft(chainCode, []byte("index-2"))
	if err != nil {
		t.Fatalf("DeriveSoft failed: %v", err)
	}

	if child1.Equal(child2) {
		t.Error("DeriveSoft produced the same child for two different indices")
	}
}
