package internal

import "testing"

func TestEllswiftEncodeDecodeRoundTrip(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	var rnd [32]byte
	rnd[0] = 0x01
	ell, ok := EllswiftEncode(pub[:], &rnd)
	if !ok {
		t.Fatal("EllswiftEncode failed for a valid key")
	}

	decoded := EllswiftDecodeCompressed(&ell)
	if decoded != pub {
		t.Error("EllswiftDecodeCompressed(EllswiftEncode(pub)) != pub")
	}
}

func TestEllswiftCreateMatchesEncode(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	ell, ok := EllswiftCreate(key, nil)
	if !ok {
		t.Fatal("EllswiftCreate failed for a valid key")
	}

	// EllswiftCreate is documented as equivalent to deriving the pubkey and
	// then encoding it, modulo the encoding's inherent randomization — so the
	// only thing checkable without reimplementing the encoder is that it
	// decodes back to the same point.
	decoded := EllswiftDecodeCompressed(&ell)
	if decoded != pub {
		t.Error("EllswiftDecodeCompressed(EllswiftCreate(seckey)) != pubkey(seckey)")
	}
}

func TestEllswiftEncodeVariesWithRnd(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	var rnd1, rnd2 [32]byte
	rnd1[0] = 0x01
	rnd2[0] = 0x02

	ell1, ok := EllswiftEncode(pub[:], &rnd1)
	if !ok {
		t.Fatal("EllswiftEncode failed for a valid key")
	}
	ell2, ok := EllswiftEncode(pub[:], &rnd2)
	if !ok {
		t.Fatal("EllswiftEncode failed for a valid key")
	}

	if ell1 == ell2 {
		t.Error("EllswiftEncode produced identical output for different rnd")
	}
	if EllswiftDecodeCompressed(&ell1) != pub || EllswiftDecodeCompressed(&ell2) != pub {
		t.Error("both encodings must still decode back to the same point")
	}
}

func TestEllswiftECDHSymmetric(t *testing.T) {
	keyA := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	keyB := seckey(t, "0000000000000000000000000000000000000000000000000000000000000002")

	ellA, ok := EllswiftCreate(keyA, nil)
	if !ok {
		t.Fatal("EllswiftCreate failed for a valid key")
	}
	ellB, ok := EllswiftCreate(keyB, nil)
	if !ok {
		t.Fatal("EllswiftCreate failed for a valid key")
	}

	secretA, ok := EllswiftECDH(&ellA, &ellB, keyA, false)
	if !ok {
		t.Fatal("EllswiftECDH failed for valid inputs")
	}
	secretB, ok := EllswiftECDH(&ellA, &ellB, keyB, true)
	if !ok {
		t.Fatal("EllswiftECDH failed for valid inputs")
	}

	if secretA != secretB {
		t.Error("EllswiftECDH(A's key, party=false) != EllswiftECDH(B's key, party=true)")
	}
}

func TestEllswiftDoesNotAllocate(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	otherKey := seckey(t, "0000000000000000000000000000000000000000000000000000000000000002")
	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}
	var rnd [32]byte
	ell, ok := EllswiftEncode(pub[:], &rnd)
	if !ok {
		t.Fatal("EllswiftEncode failed for a valid key")
	}
	otherEll, ok := EllswiftCreate(otherKey, nil)
	if !ok {
		t.Fatal("EllswiftCreate failed for a valid key")
	}

	checks := []struct {
		name string
		fn   func()
	}{
		{"EllswiftEncode", func() { EllswiftEncode(pub[:], &rnd) }},
		{"EllswiftDecodeCompressed", func() { EllswiftDecodeCompressed(&ell) }},
		{"EllswiftCreate", func() { EllswiftCreate(key, nil) }},
		{"EllswiftECDH", func() { EllswiftECDH(&ell, &otherEll, key, false) }},
	}

	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			if got := testing.AllocsPerRun(100, c.fn); got != 0 {
				t.Errorf("%s allocated %v times per run, want 0", c.name, got)
			}
		})
	}
}
