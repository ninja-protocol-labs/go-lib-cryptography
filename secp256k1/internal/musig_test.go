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

func TestMusigNonceGenZeroesSessionSecrand(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	var secrand [32]byte
	secrand[0] = 0x01 // must be non-zero: an all-zero secrand is documented as invalid input
	_, _, ok = MusigNonceGen(&secrand, nil, pub[:], nil, nil, nil)
	if !ok {
		t.Fatal("MusigNonceGen failed for valid inputs")
	}

	var zero [32]byte
	if secrand != zero {
		t.Error("MusigNonceGen did not zero sessionSecrand after consuming it")
	}
}

func TestMusigNonceGenUniqueness(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	var secrand1, secrand2 [32]byte
	secrand1[0] = 0x01
	secrand2[0] = 0x02

	secnonce1, pubnonce1, ok := MusigNonceGen(&secrand1, nil, pub[:], nil, nil, nil)
	if !ok {
		t.Fatal("MusigNonceGen failed for valid inputs")
	}
	secnonce2, pubnonce2, ok := MusigNonceGen(&secrand2, nil, pub[:], nil, nil, nil)
	if !ok {
		t.Fatal("MusigNonceGen failed for valid inputs")
	}

	if secnonce1 == secnonce2 || pubnonce1 == pubnonce2 {
		t.Error("MusigNonceGen produced identical nonces for different sessionSecrand")
	}
}

func TestMusigNonceGenWithOptionalInputs(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}
	m := msg32(t, testMsg)
	_, cache, ok := MusigPubkeyAgg(musigPubkeys(t,
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000000000000000000000000000000000000000000000000002",
	))
	if !ok {
		t.Fatal("MusigPubkeyAgg failed for valid inputs")
	}
	var extra [32]byte
	extra[0] = 0x99

	var secrand [32]byte
	secrand[0] = 0x01
	if _, _, ok := MusigNonceGen(&secrand, key, pub[:], m, &cache, &extra); !ok {
		t.Error("MusigNonceGen failed when every optional input was supplied")
	}
}

func TestMusigNonceGenRejectsEmptyPubkey(t *testing.T) {
	var secrand [32]byte
	secrand[0] = 0x01
	if _, _, ok := MusigNonceGen(&secrand, nil, nil, nil, nil, nil); ok {
		t.Error("MusigNonceGen succeeded with an empty pubkey")
	}
}

func TestMusigNonceGenCounterUniqueness(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")

	secnonce1, pubnonce1, ok := MusigNonceGenCounter(key, 1, nil, nil, nil)
	if !ok {
		t.Fatal("MusigNonceGenCounter failed for valid inputs")
	}
	secnonce2, pubnonce2, ok := MusigNonceGenCounter(key, 2, nil, nil, nil)
	if !ok {
		t.Fatal("MusigNonceGenCounter failed for valid inputs")
	}

	if secnonce1 == secnonce2 || pubnonce1 == pubnonce2 {
		t.Error("MusigNonceGenCounter produced identical nonces for different counters")
	}
}

func TestMusigNonceGenCounterRejectsInvalidSeckey(t *testing.T) {
	zero := seckey(t, "0000000000000000000000000000000000000000000000000000000000000000")
	if _, _, ok := MusigNonceGenCounter(zero, 1, nil, nil, nil); ok {
		t.Error("MusigNonceGenCounter succeeded with an invalid (zero) seckey")
	}
}

func TestMusigNonceGenDoesNotAllocate(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	if got := testing.AllocsPerRun(100, func() {
		var secrand [32]byte
		secrand[0] = 0x01
		MusigNonceGen(&secrand, nil, pub[:], nil, nil, nil)
	}); got != 0 {
		t.Errorf("MusigNonceGen allocated %v times per run, want 0", got)
	}

	var cnt uint64
	if got := testing.AllocsPerRun(100, func() {
		cnt++
		MusigNonceGenCounter(key, cnt, nil, nil, nil)
	}); got != 0 {
		t.Errorf("MusigNonceGenCounter allocated %v times per run, want 0", got)
	}
}

// A minimal 2-signer setup through nonce_process, reused by several tests
// below: aggregates two keys, generates each signer's nonce pair, aggregates
// the pubnonces, and processes them into a session.
type musigTwoSignerSession struct {
	key1, key2 *[SeckeyLen]byte
	pub1, pub2 [PubkeyCompressedLen]byte
	cache      [MusigKeyaggCacheLen]byte
	secnonce1  [MusigSecnonceLen]byte
	pubnonce1  [MusigPubnonceLen]byte
	secnonce2  [MusigSecnonceLen]byte
	pubnonce2  [MusigPubnonceLen]byte
	aggnonce   [MusigAggnonceLen]byte
	session    [MusigSessionLen]byte
}

func newMusigTwoSignerSession(t *testing.T) musigTwoSignerSession {
	t.Helper()

	key1 := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	key2 := seckey(t, "0000000000000000000000000000000000000000000000000000000000000002")
	pub1, ok := PubkeyCreateCompressed(key1)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}
	pub2, ok := PubkeyCreateCompressed(key2)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	_, cache, ok := MusigPubkeyAgg([][PubkeyCompressedLen]byte{pub1, pub2})
	if !ok {
		t.Fatal("MusigPubkeyAgg failed for valid inputs")
	}

	var secrand1, secrand2 [32]byte
	secrand1[0] = 0x01
	secrand2[0] = 0x02
	secnonce1, pubnonce1, ok := MusigNonceGen(&secrand1, key1, pub1[:], nil, nil, nil)
	if !ok {
		t.Fatal("MusigNonceGen failed for valid inputs")
	}
	secnonce2, pubnonce2, ok := MusigNonceGen(&secrand2, key2, pub2[:], nil, nil, nil)
	if !ok {
		t.Fatal("MusigNonceGen failed for valid inputs")
	}

	aggnonce, ok := MusigNonceAgg([][MusigPubnonceLen]byte{pubnonce1, pubnonce2})
	if !ok {
		t.Fatal("MusigNonceAgg failed for valid inputs")
	}

	m := msg32(t, testMsg)
	session, ok := MusigNonceProcess(&aggnonce, m, &cache)
	if !ok {
		t.Fatal("MusigNonceProcess failed for valid inputs")
	}

	return musigTwoSignerSession{
		key1: key1, key2: key2, pub1: pub1, pub2: pub2,
		cache: cache, secnonce1: secnonce1, pubnonce1: pubnonce1,
		secnonce2: secnonce2, pubnonce2: pubnonce2, aggnonce: aggnonce, session: session,
	}
}

func TestMusigPubnonceSerializeParseRoundTrip(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}
	var secrand [32]byte
	secrand[0] = 0x01
	_, pubnonce, ok := MusigNonceGen(&secrand, nil, pub[:], nil, nil, nil)
	if !ok {
		t.Fatal("MusigNonceGen failed for valid inputs")
	}

	wire := MusigPubnonceSerialize(&pubnonce)
	parsed, ok := MusigPubnonceParse(&wire)
	if !ok {
		t.Fatal("MusigPubnonceParse failed for a valid encoding")
	}

	if parsed != pubnonce {
		t.Error("MusigPubnonceParse(MusigPubnonceSerialize(pubnonce)) != pubnonce")
	}
}

func TestMusigPubnonceParseRejectsInvalid(t *testing.T) {
	var garbage [MusigPubnonceSerializedLen]byte
	for i := range garbage {
		garbage[i] = 0xff
	}
	if _, ok := MusigPubnonceParse(&garbage); ok {
		t.Error("MusigPubnonceParse succeeded for a malformed encoding")
	}
}

func TestMusigAggnonceSerializeParseRoundTrip(t *testing.T) {
	s := newMusigTwoSignerSession(t)

	wire := MusigAggnonceSerialize(&s.aggnonce)
	parsed, ok := MusigAggnonceParse(&wire)
	if !ok {
		t.Fatal("MusigAggnonceParse failed for a valid encoding")
	}

	if parsed != s.aggnonce {
		t.Error("MusigAggnonceParse(MusigAggnonceSerialize(aggnonce)) != aggnonce")
	}
}

func TestMusigNonceAggRejectsTooManyOrTooFew(t *testing.T) {
	if _, ok := MusigNonceAgg(nil); ok {
		t.Error("MusigNonceAgg succeeded with zero pubnonces")
	}

	s := newMusigTwoSignerSession(t)
	tooMany := make([][MusigPubnonceLen]byte, MaxCombinePubkeys+1)
	for i := range tooMany {
		tooMany[i] = s.pubnonce1
	}
	if _, ok := MusigNonceAgg(tooMany); ok {
		t.Error("MusigNonceAgg succeeded with more than MaxCombinePubkeys pubnonces")
	}
}

func TestMusigNonceProcessSucceeds(t *testing.T) {
	// newMusigTwoSignerSession already asserts every step including
	// MusigNonceProcess succeeds; this test exists so that success has an
	// explicit name in test output, not just as a side effect of setup.
	// hackhackhackhackhackhackhackhackhackhackhackhackhackhackhackhack
	_ = newMusigTwoSignerSession(t)
}

func TestMusigNonceExchangeDoesNotAllocate(t *testing.T) {
	s := newMusigTwoSignerSession(t)
	m := msg32(t, testMsg)
	wire := MusigPubnonceSerialize(&s.pubnonce1)
	aggWire := MusigAggnonceSerialize(&s.aggnonce)

	checks := []struct {
		name string
		fn   func()
	}{
		{"MusigPubnonceParse", func() { MusigPubnonceParse(&wire) }},
		{"MusigPubnonceSerialize", func() { MusigPubnonceSerialize(&s.pubnonce1) }},
		{"MusigAggnonceParse", func() { MusigAggnonceParse(&aggWire) }},
		{"MusigAggnonceSerialize", func() { MusigAggnonceSerialize(&s.aggnonce) }},
		{"MusigNonceAgg", func() { MusigNonceAgg([][MusigPubnonceLen]byte{s.pubnonce1, s.pubnonce2}) }},
		{"MusigNonceProcess", func() { MusigNonceProcess(&s.aggnonce, m, &s.cache) }},
	}

	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			if got := testing.AllocsPerRun(100, c.fn); got != 0 {
				t.Errorf("%s allocated %v times per run, want 0", c.name, got)
			}
		})
	}
}

func TestMusigPartialSignVerifyRoundTrip(t *testing.T) {
	s := newMusigTwoSignerSession(t)

	sig1, ok := MusigPartialSign(&s.secnonce1, s.key1, &s.cache, &s.session)
	if !ok {
		t.Fatal("MusigPartialSign failed for valid inputs")
	}

	if !MusigPartialSigVerify(&sig1, &s.pubnonce1, s.pub1[:], &s.cache, &s.session) {
		t.Error("MusigPartialSigVerify rejected a partial signature it should accept")
	}
}

func TestMusigPartialSignZeroesSecnonce(t *testing.T) {
	s := newMusigTwoSignerSession(t)

	if _, ok := MusigPartialSign(&s.secnonce1, s.key1, &s.cache, &s.session); !ok {
		t.Fatal("MusigPartialSign failed for valid inputs")
	}

	var zero [MusigSecnonceLen]byte
	if s.secnonce1 != zero {
		t.Error("MusigPartialSign did not zero secnonce after consuming it")
	}
}

func TestMusigPartialSignRejectsReusedSecnonce(t *testing.T) {
	s := newMusigTwoSignerSession(t)

	if _, ok := MusigPartialSign(&s.secnonce1, s.key1, &s.cache, &s.session); !ok {
		t.Fatal("MusigPartialSign failed for valid inputs")
	}

	// secnonce1 is now all-zero (consumed above); signing again with it must
	// fail cleanly rather than succeed or reuse anything.
	if _, ok := MusigPartialSign(&s.secnonce1, s.key1, &s.cache, &s.session); ok {
		t.Error("MusigPartialSign succeeded when reusing an already-consumed secnonce")
	}
}

func TestMusigPartialSigVerifyRejectsWrongPubnonce(t *testing.T) {
	s := newMusigTwoSignerSession(t)

	sig1, ok := MusigPartialSign(&s.secnonce1, s.key1, &s.cache, &s.session)
	if !ok {
		t.Fatal("MusigPartialSign failed for valid inputs")
	}

	if MusigPartialSigVerify(&sig1, &s.pubnonce2, s.pub1[:], &s.cache, &s.session) {
		t.Error("MusigPartialSigVerify accepted a signature checked against the wrong signer's pubnonce")
	}
}

func TestMusigPartialSigVerifyRejectsWrongPubkey(t *testing.T) {
	s := newMusigTwoSignerSession(t)

	sig1, ok := MusigPartialSign(&s.secnonce1, s.key1, &s.cache, &s.session)
	if !ok {
		t.Fatal("MusigPartialSign failed for valid inputs")
	}

	if MusigPartialSigVerify(&sig1, &s.pubnonce1, s.pub2[:], &s.cache, &s.session) {
		t.Error("MusigPartialSigVerify accepted a signature checked against the wrong signer's pubkey")
	}
}

func TestMusigPartialSigSerializeParseRoundTrip(t *testing.T) {
	s := newMusigTwoSignerSession(t)

	sig1, ok := MusigPartialSign(&s.secnonce1, s.key1, &s.cache, &s.session)
	if !ok {
		t.Fatal("MusigPartialSign failed for valid inputs")
	}

	wire := MusigPartialSigSerialize(&sig1)
	parsed, ok := MusigPartialSigParse(&wire)
	if !ok {
		t.Fatal("MusigPartialSigParse failed for a valid encoding")
	}

	if parsed != sig1 {
		t.Error("MusigPartialSigParse(MusigPartialSigSerialize(sig)) != sig")
	}
}

func TestMusigPartialSigParseRejectsInvalid(t *testing.T) {
	var garbage [MusigPartialSigSerializedLen]byte
	for i := range garbage {
		garbage[i] = 0xff
	}
	if _, ok := MusigPartialSigParse(&garbage); ok {
		t.Error("MusigPartialSigParse succeeded for a malformed encoding")
	}
}

func TestMusigPartialSignVerifyDoesNotAllocate(t *testing.T) {
	s := newMusigTwoSignerSession(t)

	if got := testing.AllocsPerRun(100, func() {
		// MusigPartialSign consumes secnonce, so each iteration needs its
		// own copy — reusing s.secnonce1 across iterations would fail from
		// the second call on.
		secnonce := s.secnonce1
		sig1, ok := MusigPartialSign(&secnonce, s.key1, &s.cache, &s.session)
		if !ok {
			t.Fatal("MusigPartialSign failed for valid inputs")
		}
		if !MusigPartialSigVerify(&sig1, &s.pubnonce1, s.pub1[:], &s.cache, &s.session) {
			t.Fatal("MusigPartialSigVerify failed for valid inputs")
		}
	}); got != 0 {
		t.Errorf("MusigPartialSign+MusigPartialSigVerify allocated %v times per run, want 0", got)
	}
}

// The capstone test: a complete 2-signer MuSig2 session, end to end, whose
// final output is a signature verified by the ordinary, protocol-agnostic
// SchnorrVerify — proving MuSig2's aggregate signature really is just a
// normal Schnorr signature over the aggregate key from the signer's
// perspective, exactly as the scheme promises.
func TestMusigPartialSigAggProducesValidSignature(t *testing.T) {
	s := newMusigTwoSignerSession(t)
	aggPk, _, ok := MusigPubkeyAgg([][PubkeyCompressedLen]byte{s.pub1, s.pub2})
	if !ok {
		t.Fatal("MusigPubkeyAgg failed for valid inputs")
	}

	sig1, ok := MusigPartialSign(&s.secnonce1, s.key1, &s.cache, &s.session)
	if !ok {
		t.Fatal("MusigPartialSign failed for valid inputs")
	}
	sig2, ok := MusigPartialSign(&s.secnonce2, s.key2, &s.cache, &s.session)
	if !ok {
		t.Fatal("MusigPartialSign failed for valid inputs")
	}

	if !MusigPartialSigVerify(&sig1, &s.pubnonce1, s.pub1[:], &s.cache, &s.session) {
		t.Fatal("MusigPartialSigVerify rejected signer 1's own partial signature")
	}
	if !MusigPartialSigVerify(&sig2, &s.pubnonce2, s.pub2[:], &s.cache, &s.session) {
		t.Fatal("MusigPartialSigVerify rejected signer 2's own partial signature")
	}

	finalSig, ok := MusigPartialSigAgg(&s.session, [][MusigPartialSigLen]byte{sig1, sig2})
	if !ok {
		t.Fatal("MusigPartialSigAgg failed for valid inputs")
	}

	m := msg32(t, testMsg)
	if !SchnorrVerify(m[:], &aggPk, &finalSig) {
		t.Error("the aggregated MuSig2 signature does not verify as an ordinary Schnorr signature over the aggregate key")
	}
}

func TestMusigPartialSigAggRejectsTooManyOrTooFew(t *testing.T) {
	s := newMusigTwoSignerSession(t)

	if _, ok := MusigPartialSigAgg(&s.session, nil); ok {
		t.Error("MusigPartialSigAgg succeeded with zero partial signatures")
	}

	sig1, ok := MusigPartialSign(&s.secnonce1, s.key1, &s.cache, &s.session)
	if !ok {
		t.Fatal("MusigPartialSign failed for valid inputs")
	}
	tooMany := make([][MusigPartialSigLen]byte, MaxCombinePubkeys+1)
	for i := range tooMany {
		tooMany[i] = sig1
	}
	if _, ok := MusigPartialSigAgg(&s.session, tooMany); ok {
		t.Error("MusigPartialSigAgg succeeded with more than MaxCombinePubkeys partial signatures")
	}
}

func TestMusigPartialSigAggDoesNotAllocate(t *testing.T) {
	s := newMusigTwoSignerSession(t)
	sig1, ok := MusigPartialSign(&s.secnonce1, s.key1, &s.cache, &s.session)
	if !ok {
		t.Fatal("MusigPartialSign failed for valid inputs")
	}
	sig2, ok := MusigPartialSign(&s.secnonce2, s.key2, &s.cache, &s.session)
	if !ok {
		t.Fatal("MusigPartialSign failed for valid inputs")
	}
	partialSigs := [][MusigPartialSigLen]byte{sig1, sig2}

	if got := testing.AllocsPerRun(100, func() { MusigPartialSigAgg(&s.session, partialSigs) }); got != 0 {
		t.Errorf("MusigPartialSigAgg allocated %v times per run, want 0", got)
	}
}
