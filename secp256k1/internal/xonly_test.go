package internal

import "testing"

func TestXonlyPubkeyCreateMatchesFromPubkey(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")

	fromSeckey, parity1, ok := XonlyPubkeyCreate(key)
	if !ok {
		t.Fatal("XonlyPubkeyCreate failed for a valid key")
	}

	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}
	fromPubkey, parity2, ok := XonlyPubkeyFromPubkey(pub[:])
	if !ok {
		t.Fatal("XonlyPubkeyFromPubkey failed for a valid key")
	}

	if fromSeckey != fromPubkey {
		t.Error("XonlyPubkeyCreate and XonlyPubkeyFromPubkey disagree on the x-only key")
	}
	if parity1 != parity2 {
		t.Errorf("XonlyPubkeyCreate parity = %d, XonlyPubkeyFromPubkey parity = %d, want equal", parity1, parity2)
	}
}

func TestXonlyPubkeyVerify(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	valid, _, ok := XonlyPubkeyCreate(key)
	if !ok {
		t.Fatal("XonlyPubkeyCreate failed for a valid key")
	}

	if !XonlyPubkeyVerify(&valid) {
		t.Error("XonlyPubkeyVerify rejected a valid x-only key")
	}

	var invalid [XonlyPubkeyLen]byte
	for i := range invalid {
		invalid[i] = 0xff
	}
	if XonlyPubkeyVerify(&invalid) {
		t.Error("XonlyPubkeyVerify accepted a key with no valid x coordinate")
	}
}

func TestXonlyPubkeyCmp(t *testing.T) {
	pub1, _, ok := XonlyPubkeyCreate(seckey(t, "0000000000000000000000000000000000000000000000000000000000000001"))
	if !ok {
		t.Fatal("XonlyPubkeyCreate failed for a valid key")
	}
	pub2, _, ok := XonlyPubkeyCreate(seckey(t, "0000000000000000000000000000000000000000000000000000000000000002"))
	if !ok {
		t.Fatal("XonlyPubkeyCreate failed for a valid key")
	}

	result, ok := XonlyPubkeyCmp(&pub1, &pub1)
	if !ok || result != 0 {
		t.Errorf("XonlyPubkeyCmp(pub1, pub1) = %d, %v, want 0, true", result, ok)
	}

	result, ok = XonlyPubkeyCmp(&pub1, &pub2)
	if !ok {
		t.Fatal("XonlyPubkeyCmp failed for valid inputs")
	}
	reverse, ok := XonlyPubkeyCmp(&pub2, &pub1)
	if !ok {
		t.Fatal("XonlyPubkeyCmp failed for valid inputs")
	}
	if result == 0 || result != -reverse {
		t.Errorf("XonlyPubkeyCmp(a, b) = %d, XonlyPubkeyCmp(b, a) = %d, want opposite signs", result, reverse)
	}
}

func TestXonlyPubkeyTweakAddAndCheck(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	tweak := seckey(t, "0000000000000000000000000000000000000000000000000000000000000002")

	internal, _, ok := XonlyPubkeyCreate(key)
	if !ok {
		t.Fatal("XonlyPubkeyCreate failed for a valid key")
	}

	tweaked, parity, ok := XonlyPubkeyTweakAdd(&internal, tweak)
	if !ok {
		t.Fatal("XonlyPubkeyTweakAdd failed for valid inputs")
	}

	if !XonlyPubkeyTweakAddCheck(&tweaked, parity, &internal, tweak) {
		t.Error("XonlyPubkeyTweakAddCheck rejected a tweak it should accept")
	}

	wrongTweak := seckey(t, "0000000000000000000000000000000000000000000000000000000000000003")
	if XonlyPubkeyTweakAddCheck(&tweaked, parity, &internal, wrongTweak) {
		t.Error("XonlyPubkeyTweakAddCheck accepted the wrong tweak")
	}
}

func TestSeckeyXonlyTweakAddMatchesPubkeyTweak(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	tweak := seckey(t, "0000000000000000000000000000000000000000000000000000000000000002")

	internal, _, ok := XonlyPubkeyCreate(key)
	if !ok {
		t.Fatal("XonlyPubkeyCreate failed for a valid key")
	}
	wantXonly, wantParity, ok := XonlyPubkeyTweakAdd(&internal, tweak)
	if !ok {
		t.Fatal("XonlyPubkeyTweakAdd failed for valid inputs")
	}

	tweakedSeckey := *key
	if !SeckeyXonlyTweakAdd(&tweakedSeckey, tweak) {
		t.Fatal("SeckeyXonlyTweakAdd failed for valid inputs")
	}
	gotXonly, gotParity, ok := XonlyPubkeyCreate(&tweakedSeckey)
	if !ok {
		t.Fatal("XonlyPubkeyCreate failed for the tweaked key")
	}

	if gotXonly != wantXonly {
		t.Error("SeckeyXonlyTweakAdd's x-only pubkey does not match XonlyPubkeyTweakAdd's")
	}
	if gotParity != wantParity {
		t.Errorf("SeckeyXonlyTweakAdd parity = %d, XonlyPubkeyTweakAdd parity = %d, want equal", gotParity, wantParity)
	}
}

func TestXonlyDoesNotAllocate(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	tweak := seckey(t, "0000000000000000000000000000000000000000000000000000000000000002")
	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}
	xonly, _, ok := XonlyPubkeyCreate(key)
	if !ok {
		t.Fatal("XonlyPubkeyCreate failed for a valid key")
	}
	tweaked, tweakedParity, ok := XonlyPubkeyTweakAdd(&xonly, tweak)
	if !ok {
		t.Fatal("XonlyPubkeyTweakAdd failed for valid inputs")
	}

	checks := []struct {
		name string
		fn   func()
	}{
		{"XonlyPubkeyCreate", func() { XonlyPubkeyCreate(key) }},
		{"XonlyPubkeyVerify", func() { XonlyPubkeyVerify(&xonly) }},
		{"XonlyPubkeyFromPubkey", func() { XonlyPubkeyFromPubkey(pub[:]) }},
		{"XonlyPubkeyCmp", func() { XonlyPubkeyCmp(&xonly, &xonly) }},
		{"XonlyPubkeyTweakAdd", func() { XonlyPubkeyTweakAdd(&xonly, tweak) }},
		{"XonlyPubkeyTweakAddCheck", func() { XonlyPubkeyTweakAddCheck(&tweaked, tweakedParity, &xonly, tweak) }},
		{"SeckeyXonlyTweakAdd", func() { k := *key; SeckeyXonlyTweakAdd(&k, tweak) }},
	}

	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			if got := testing.AllocsPerRun(100, c.fn); got != 0 {
				t.Errorf("%s allocated %v times per run, want 0", c.name, got)
			}
		})
	}
}
