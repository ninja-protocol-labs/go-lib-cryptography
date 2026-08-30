package internal

import "testing"

func musigPubkeys(t *testing.T, seckeys ...string) [][PubkeyCompressedLen]byte {
	t.Helper()
	out := make([][PubkeyCompressedLen]byte, len(seckeys))
	for i, s := range seckeys {
		pub, ok := PubkeyCreateCompressed(seckey(t, s))
		if !ok {
			t.Fatalf("PubkeyCreateCompressed failed for a valid key %q", s)
		}
		out[i] = pub
	}
	return out
}

func TestMusigPubkeyAggIsDeterministic(t *testing.T) {
	pubkeys := musigPubkeys(t,
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000000000000000000000000000000000000000000000000002",
	)

	aggPk1, _, ok := MusigPubkeyAgg(pubkeys)
	if !ok {
		t.Fatal("MusigPubkeyAgg failed for valid inputs")
	}
	aggPk2, _, ok := MusigPubkeyAgg(pubkeys)
	if !ok {
		t.Fatal("MusigPubkeyAgg failed for valid inputs")
	}

	if aggPk1 != aggPk2 {
		t.Error("MusigPubkeyAgg produced different results for the same input")
	}
}

func TestMusigPubkeyAggOrderMatters(t *testing.T) {
	pubkeys := musigPubkeys(t,
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000000000000000000000000000000000000000000000000002",
	)
	reversed := [][PubkeyCompressedLen]byte{pubkeys[1], pubkeys[0]}

	aggPk, _, ok := MusigPubkeyAgg(pubkeys)
	if !ok {
		t.Fatal("MusigPubkeyAgg failed for valid inputs")
	}
	reversedAggPk, _, ok := MusigPubkeyAgg(reversed)
	if !ok {
		t.Fatal("MusigPubkeyAgg failed for valid inputs")
	}

	if aggPk == reversedAggPk {
		t.Error("MusigPubkeyAgg gave the same result for two different key orders")
	}
}

func TestMusigPubkeyAggRejectsTooManyOrTooFew(t *testing.T) {
	if _, _, ok := MusigPubkeyAgg(nil); ok {
		t.Error("MusigPubkeyAgg succeeded with zero keys")
	}

	key := musigPubkeys(t, "0000000000000000000000000000000000000000000000000000000000000001")[0]
	tooMany := make([][PubkeyCompressedLen]byte, MaxCombinePubkeys+1)
	for i := range tooMany {
		tooMany[i] = key
	}
	if _, _, ok := MusigPubkeyAgg(tooMany); ok {
		t.Error("MusigPubkeyAgg succeeded with more than MaxCombinePubkeys keys")
	}
}

func TestMusigPubkeyGetMatchesAgg(t *testing.T) {
	pubkeys := musigPubkeys(t,
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000000000000000000000000000000000000000000000000002",
	)

	aggPk, cache, ok := MusigPubkeyAgg(pubkeys)
	if !ok {
		t.Fatal("MusigPubkeyAgg failed for valid inputs")
	}

	fullPk, ok := MusigPubkeyGetCompressed(&cache)
	if !ok {
		t.Fatal("MusigPubkeyGetCompressed failed for a valid cache")
	}

	// aggPk is the x-only serialization of the same point MusigPubkeyGet
	// returns in full form, so converting the full form to x-only must
	// reproduce it.
	xonly, _, ok := XonlyPubkeyFromPubkey(fullPk[:])
	if !ok {
		t.Fatal("XonlyPubkeyFromPubkey failed for a valid pubkey")
	}
	if xonly != aggPk {
		t.Error("x-only(MusigPubkeyGet(cache)) != MusigPubkeyAgg's aggregate x-only key")
	}
}

// The header documents that shim_musig_pubkey_ec_tweak_add uses the same
// tweaking method as plain EC tweaking: tweaking the aggregate key through
// the cache must produce the same point as tweaking the already-recovered
// full key directly with PubkeyTweakAddCompressed.
func TestMusigPubkeyECTweakAddMatchesPlainTweak(t *testing.T) {
	pubkeys := musigPubkeys(t,
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000000000000000000000000000000000000000000000000002",
	)
	tweak := seckey(t, "0000000000000000000000000000000000000000000000000000000000000003")

	_, cache, ok := MusigPubkeyAgg(pubkeys)
	if !ok {
		t.Fatal("MusigPubkeyAgg failed for valid inputs")
	}
	fullPk, ok := MusigPubkeyGetCompressed(&cache)
	if !ok {
		t.Fatal("MusigPubkeyGetCompressed failed for a valid cache")
	}

	want, ok := PubkeyTweakAddCompressed(fullPk[:], tweak)
	if !ok {
		t.Fatal("PubkeyTweakAddCompressed failed for valid inputs")
	}
	got, ok := MusigPubkeyECTweakAddCompressed(&cache, tweak)
	if !ok {
		t.Fatal("MusigPubkeyECTweakAddCompressed failed for valid inputs")
	}

	if got != want {
		t.Error("MusigPubkeyECTweakAddCompressed does not match PubkeyTweakAddCompressed on the recovered full key")
	}
}

// Mirrors the header's documented pseudocode: after
// MusigPubkeyXonlyTweakAdd, the resulting key's x-only form must pass
// XonlyPubkeyTweakAddCheck against the original aggregate x-only key.
func TestMusigPubkeyXonlyTweakAddCheck(t *testing.T) {
	pubkeys := musigPubkeys(t,
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000000000000000000000000000000000000000000000000002",
	)
	tweak := seckey(t, "0000000000000000000000000000000000000000000000000000000000000003")

	aggPk, cache, ok := MusigPubkeyAgg(pubkeys)
	if !ok {
		t.Fatal("MusigPubkeyAgg failed for valid inputs")
	}

	tweakedPk, ok := MusigPubkeyXonlyTweakAddCompressed(&cache, tweak)
	if !ok {
		t.Fatal("MusigPubkeyXonlyTweakAddCompressed failed for valid inputs")
	}

	tweakedXonly, parity, ok := XonlyPubkeyFromPubkey(tweakedPk[:])
	if !ok {
		t.Fatal("XonlyPubkeyFromPubkey failed for a valid pubkey")
	}

	if !XonlyPubkeyTweakAddCheck(&tweakedXonly, parity, &aggPk, tweak) {
		t.Error("XonlyPubkeyTweakAddCheck rejected the result of MusigPubkeyXonlyTweakAddCompressed")
	}
}

func TestMusigKeyAggDoesNotAllocate(t *testing.T) {
	pubkeys := musigPubkeys(t,
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000000000000000000000000000000000000000000000000002",
	)
	tweak := seckey(t, "0000000000000000000000000000000000000000000000000000000000000003")
	_, cache, ok := MusigPubkeyAgg(pubkeys)
	if !ok {
		t.Fatal("MusigPubkeyAgg failed for valid inputs")
	}

	checks := []struct {
		name string
		fn   func()
	}{
		{"MusigPubkeyAgg", func() { MusigPubkeyAgg(pubkeys) }},
		{"MusigPubkeyGetCompressed", func() { MusigPubkeyGetCompressed(&cache) }},
		{"MusigPubkeyECTweakAddCompressed", func() { c := cache; MusigPubkeyECTweakAddCompressed(&c, tweak) }},
		{"MusigPubkeyXonlyTweakAddCompressed", func() { c := cache; MusigPubkeyXonlyTweakAddCompressed(&c, tweak) }},
	}

	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			if got := testing.AllocsPerRun(100, c.fn); got != 0 {
				t.Errorf("%s allocated %v times per run, want 0", c.name, got)
			}
		})
	}
}
