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
