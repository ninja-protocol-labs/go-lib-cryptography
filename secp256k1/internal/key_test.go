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
