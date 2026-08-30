package internal

import (
	"encoding/hex"
	"testing"
)

// The order of the secp256k1 group. Keys are valid in [1, n-1], so n itself and
// everything above it must be rejected.
const curveOrder = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"

func seckey(t *testing.T, s string) *[SeckeyLen]byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in test case: %v", err)
	}
	if len(b) != SeckeyLen {
		t.Fatalf("test case is %d bytes, want %d", len(b), SeckeyLen)
	}

	var key [SeckeyLen]byte
	copy(key[:], b)
	return &key
}

func TestSeckeyVerify(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want bool
	}{
		{
			name: "one",
			key:  "0000000000000000000000000000000000000000000000000000000000000001",
			want: true,
		},
		{
			name: "order minus one",
			key:  "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
			want: true,
		},
		{
			name: "zero",
			key:  "0000000000000000000000000000000000000000000000000000000000000000",
			want: false,
		},
		{
			name: "order",
			key:  curveOrder,
			want: false,
		},
		{
			name: "all ones",
			key:  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SeckeyVerify(seckey(t, tt.key)); got != tt.want {
				t.Errorf("SeckeyVerify(%s) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

// The binding layer is on its callers' hot paths, so crossing into C must not
// allocate. This guards the #cgo noescape directives in shim.go: drop one and
// the argument gets moved to the heap, and this fails.
func TestSeckeyVerifyDoesNotAllocate(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")

	if got := testing.AllocsPerRun(100, func() { SeckeyVerify(key) }); got != 0 {
		t.Errorf("SeckeyVerify allocated %v times per run, want 0", got)
	}
}

// secp256k1's generator point G: the public key for private key 1. A fixed
// constant of the curve, not derived, so it makes a trustworthy test vector.
const (
	generatorCompressed   = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	generatorUncompressed = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
		"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)

func TestPubkeyCreateCompressed(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")

	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed reported failure for a valid key")
	}
	if got := hex.EncodeToString(pub[:]); got != generatorCompressed {
		t.Errorf("PubkeyCreateCompressed() = %s, want %s", got, generatorCompressed)
	}
}

func TestPubkeyCreateUncompressed(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")

	pub, ok := PubkeyCreateUncompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateUncompressed reported failure for a valid key")
	}
	if got := hex.EncodeToString(pub[:]); got != generatorUncompressed {
		t.Errorf("PubkeyCreateUncompressed() = %s, want %s", got, generatorUncompressed)
	}
}

func TestPubkeyCreateRejectsInvalidSeckey(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000000")

	if _, ok := PubkeyCreateCompressed(key); ok {
		t.Error("PubkeyCreateCompressed succeeded for the zero key")
	}
	if _, ok := PubkeyCreateUncompressed(key); ok {
		t.Error("PubkeyCreateUncompressed succeeded for the zero key")
	}
}

func TestPubkeyCreateDoesNotAllocate(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")

	if got := testing.AllocsPerRun(100, func() { PubkeyCreateCompressed(key) }); got != 0 {
		t.Errorf("PubkeyCreateCompressed allocated %v times per run, want 0", got)
	}
	if got := testing.AllocsPerRun(100, func() { PubkeyCreateUncompressed(key) }); got != 0 {
		t.Errorf("PubkeyCreateUncompressed allocated %v times per run, want 0", got)
	}
}

func TestPubkeyParse(t *testing.T) {
	compressed, err := hex.DecodeString(generatorCompressed)
	if err != nil {
		t.Fatalf("bad hex in test case: %v", err)
	}
	uncompressed, err := hex.DecodeString(generatorUncompressed)
	if err != nil {
		t.Fatalf("bad hex in test case: %v", err)
	}

	tests := []struct {
		name  string
		input []byte
	}{
		{name: "from compressed", input: compressed},
		{name: "from uncompressed", input: uncompressed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCompressed, ok := PubkeyParseCompressed(tt.input)
			if !ok {
				t.Fatal("PubkeyParseCompressed reported failure for a valid key")
			}
			if got := hex.EncodeToString(gotCompressed[:]); got != generatorCompressed {
				t.Errorf("PubkeyParseCompressed() = %s, want %s", got, generatorCompressed)
			}

			gotUncompressed, ok := PubkeyParseUncompressed(tt.input)
			if !ok {
				t.Fatal("PubkeyParseUncompressed reported failure for a valid key")
			}
			if got := hex.EncodeToString(gotUncompressed[:]); got != generatorUncompressed {
				t.Errorf("PubkeyParseUncompressed() = %s, want %s", got, generatorUncompressed)
			}
		})
	}
}

func TestPubkeyParseRejectsInvalid(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{name: "empty", input: nil},
		{name: "truncated", input: []byte{0x02, 0x79, 0xbe}},
		{name: "bad prefix byte", input: append([]byte{0xff}, make([]byte, 32)...)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := PubkeyParseCompressed(tt.input); ok {
				t.Error("PubkeyParseCompressed succeeded for an invalid encoding")
			}
			if _, ok := PubkeyParseUncompressed(tt.input); ok {
				t.Error("PubkeyParseUncompressed succeeded for an invalid encoding")
			}
		})
	}
}

func TestSeckeyPubkeyNegateRoundTrip(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	negatedKey := *key
	if !SeckeyNegate(&negatedKey) {
		t.Fatal("SeckeyNegate failed for a valid key")
	}
	if negatedKey == *key {
		t.Error("SeckeyNegate did not change the key")
	}

	negatedPub, ok := PubkeyNegateCompressed(pub[:])
	if !ok {
		t.Fatal("PubkeyNegateCompressed failed for a valid key")
	}

	// -(d*G) must equal (n-d)*G: negating the seckey and then deriving, or
	// deriving and then negating the pubkey, must land on the same point.
	wantPub, ok := PubkeyCreateCompressed(&negatedKey)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}
	if negatedPub != wantPub {
		t.Error("PubkeyNegateCompressed(pubkey) != pubkey(SeckeyNegate(seckey))")
	}

	// Negating twice must return to the original.
	twiceNegated := negatedKey
	if !SeckeyNegate(&twiceNegated) {
		t.Fatal("SeckeyNegate failed for a valid key")
	}
	if twiceNegated != *key {
		t.Error("negating a seckey twice did not reproduce the original")
	}
}

func TestPubkeyCombine(t *testing.T) {
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

	// (1*G) + (2*G) must equal 3*G.
	combined, ok := PubkeyCombineCompressed([][PubkeyCompressedLen]byte{pub1, pub2})
	if !ok {
		t.Fatal("PubkeyCombineCompressed failed for valid inputs")
	}

	key3 := seckey(t, "0000000000000000000000000000000000000000000000000000000000000003")
	want, ok := PubkeyCreateCompressed(key3)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	if combined != want {
		t.Error("PubkeyCombineCompressed(1*G, 2*G) != 3*G")
	}
}

func TestPubkeyCombineRejectsTooManyOrTooFew(t *testing.T) {
	if _, ok := PubkeyCombineCompressed(nil); ok {
		t.Error("PubkeyCombineCompressed succeeded with zero keys")
	}

	key, ok := PubkeyCreateCompressed(seckey(t, "0000000000000000000000000000000000000000000000000000000000000001"))
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}
	tooMany := make([][PubkeyCompressedLen]byte, MaxCombinePubkeys+1)
	for i := range tooMany {
		tooMany[i] = key
	}
	if _, ok := PubkeyCombineCompressed(tooMany); ok {
		t.Error("PubkeyCombineCompressed succeeded with more than MaxCombinePubkeys keys")
	}
}

func TestPubkeyCmp(t *testing.T) {
	pub1, ok := PubkeyCreateCompressed(seckey(t, "0000000000000000000000000000000000000000000000000000000000000001"))
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}
	pub2, ok := PubkeyCreateCompressed(seckey(t, "0000000000000000000000000000000000000000000000000000000000000002"))
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	result, ok := PubkeyCmp(pub1[:], pub1[:])
	if !ok || result != 0 {
		t.Errorf("PubkeyCmp(pub1, pub1) = %d, %v, want 0, true", result, ok)
	}

	result, ok = PubkeyCmp(pub1[:], pub2[:])
	if !ok {
		t.Fatal("PubkeyCmp failed for valid inputs")
	}
	reverse, ok := PubkeyCmp(pub2[:], pub1[:])
	if !ok {
		t.Fatal("PubkeyCmp failed for valid inputs")
	}
	if result == 0 || result != -reverse {
		t.Errorf("PubkeyCmp(a, b) = %d, PubkeyCmp(b, a) = %d, want opposite signs", result, reverse)
	}
}

func TestPubkeySortCompressed(t *testing.T) {
	pub1, ok := PubkeyCreateCompressed(seckey(t, "0000000000000000000000000000000000000000000000000000000000000001"))
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}
	pub2, ok := PubkeyCreateCompressed(seckey(t, "0000000000000000000000000000000000000000000000000000000000000002"))
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	// Feed them in whichever order sorts to descending, then check ascending
	// comes out — proves the call actually reordered rather than being a
	// no-op that happened to match.
	unsorted := [][PubkeyCompressedLen]byte{pub1, pub2}
	if cmp, ok := PubkeyCmp(pub1[:], pub2[:]); ok && cmp > 0 {
		unsorted[0], unsorted[1] = pub2, pub1
	}
	reversed := [][PubkeyCompressedLen]byte{unsorted[1], unsorted[0]}

	if !PubkeySortCompressed(reversed) {
		t.Fatal("PubkeySortCompressed failed for valid inputs")
	}
	if reversed[0] != unsorted[0] || reversed[1] != unsorted[1] {
		t.Error("PubkeySortCompressed did not produce ascending order")
	}
}

func TestSeckeyTweakAddMul(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000002")
	tweak := seckey(t, "0000000000000000000000000000000000000000000000000000000000000003")

	added := *key
	if !SeckeyTweakAdd(&added, tweak) {
		t.Fatal("SeckeyTweakAdd failed for valid inputs")
	}
	// 2 + 3 = 5
	want := seckey(t, "0000000000000000000000000000000000000000000000000000000000000005")
	if added != *want {
		t.Errorf("SeckeyTweakAdd(2, 3) = %x, want %x", added, *want)
	}

	multiplied := *key
	if !SeckeyTweakMul(&multiplied, tweak) {
		t.Fatal("SeckeyTweakMul failed for valid inputs")
	}
	// 2 * 3 = 6
	want = seckey(t, "0000000000000000000000000000000000000000000000000000000000000006")
	if multiplied != *want {
		t.Errorf("SeckeyTweakMul(2, 3) = %x, want %x", multiplied, *want)
	}
}

func TestPubkeyTweakAddMulMatchSeckeyTweak(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000002")
	tweak := seckey(t, "0000000000000000000000000000000000000000000000000000000000000003")
	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	addedKey := *key
	if !SeckeyTweakAdd(&addedKey, tweak) {
		t.Fatal("SeckeyTweakAdd failed for valid inputs")
	}
	wantAdded, ok := PubkeyCreateCompressed(&addedKey)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}
	gotAdded, ok := PubkeyTweakAddCompressed(pub[:], tweak)
	if !ok {
		t.Fatal("PubkeyTweakAddCompressed failed for valid inputs")
	}
	if gotAdded != wantAdded {
		t.Error("PubkeyTweakAddCompressed(pubkey, t) != pubkey(SeckeyTweakAdd(seckey, t))")
	}

	mulKey := *key
	if !SeckeyTweakMul(&mulKey, tweak) {
		t.Fatal("SeckeyTweakMul failed for valid inputs")
	}
	wantMul, ok := PubkeyCreateCompressed(&mulKey)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}
	gotMul, ok := PubkeyTweakMulCompressed(pub[:], tweak)
	if !ok {
		t.Fatal("PubkeyTweakMulCompressed failed for valid inputs")
	}
	if gotMul != wantMul {
		t.Error("PubkeyTweakMulCompressed(pubkey, t) != pubkey(SeckeyTweakMul(seckey, t))")
	}
}

func TestStep7DoesNotAllocate(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	tweak := seckey(t, "0000000000000000000000000000000000000000000000000000000000000002")
	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}
	pairs := [][PubkeyCompressedLen]byte{pub, pub}

	checks := []struct {
		name string
		fn   func()
	}{
		{"SeckeyNegate", func() { k := *key; SeckeyNegate(&k) }},
		{"PubkeyNegateCompressed", func() { PubkeyNegateCompressed(pub[:]) }},
		{"PubkeyCombineCompressed", func() { PubkeyCombineCompressed(pairs) }},
		{"PubkeyCmp", func() { PubkeyCmp(pub[:], pub[:]) }},
		{"PubkeySortCompressed", func() { p := pairs; PubkeySortCompressed(p) }},
		{"SeckeyTweakAdd", func() { k := *key; SeckeyTweakAdd(&k, tweak) }},
		{"SeckeyTweakMul", func() { k := *key; SeckeyTweakMul(&k, tweak) }},
		{"PubkeyTweakAddCompressed", func() { PubkeyTweakAddCompressed(pub[:], tweak) }},
		{"PubkeyTweakMulCompressed", func() { PubkeyTweakMulCompressed(pub[:], tweak) }},
	}

	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			if got := testing.AllocsPerRun(100, c.fn); got != 0 {
				t.Errorf("%s allocated %v times per run, want 0", c.name, got)
			}
		})
	}
}

func TestPubkeyParseDoesNotAllocate(t *testing.T) {
	compressed, err := hex.DecodeString(generatorCompressed)
	if err != nil {
		t.Fatalf("bad hex in test case: %v", err)
	}

	if got := testing.AllocsPerRun(100, func() { PubkeyParseCompressed(compressed) }); got != 0 {
		t.Errorf("PubkeyParseCompressed allocated %v times per run, want 0", got)
	}
	if got := testing.AllocsPerRun(100, func() { PubkeyParseUncompressed(compressed) }); got != 0 {
		t.Errorf("PubkeyParseUncompressed allocated %v times per run, want 0", got)
	}
}
