package scrypt

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	upstream "golang.org/x/crypto/scrypt"
)

// The RFC 7914 §11 test vectors, regenerated with Python's hashlib.scrypt and
// cross-checked against OpenSSL's SCRYPT KDF rather than taken from the
// library this package wraps — deriving with x/crypto and comparing against
// x/crypto would only show the wrapper is self-consistent.
//
// The RFC's fourth vector (N=1048576) is omitted: a gibibyte of memory and
// seconds of work for no coverage the third does not already give.
var vectors = []struct {
	name     string
	password string
	salt     string
	N, r, p  int
	want     string
}{
	{
		"empty password and salt", "", "", 16, 1, 1,
		"77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442" +
			"fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
	},
	{
		// p=16, the only vector here that exercises parallelism.
		"N=1024 r=8 p=16", "password", "NaCl", 1024, 8, 16,
		"fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162" +
			"2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
	},
	{
		// The RFC's own illustrative parameters for an interactive login.
		"N=16384 r=8 p=1", "pleaseletmein", "SodiumChloride", 16384, 8, 1,
		"7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2" +
			"d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
	},
}

// Cheap parameters for the tests that are about behaviour rather than known
// answers, so the suite stays fast: 2 KiB and a trivial amount of mixing.
const (
	testN = 16
	testR = 1
	testP = 1
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad test vector %q: %v", s, err)
	}
	return b
}

func key(t *testing.T, password, salt string, keyLen int) []byte {
	t.Helper()
	k, err := Key([]byte(password), []byte(salt), testN, testR, testP, keyLen)
	if err != nil {
		t.Fatalf("Key failed: %v", err)
	}
	return k
}

func TestKeyMatchesKnownAnswers(t *testing.T) {
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			want := mustDecodeHex(t, v.want)
			got, err := Key([]byte(v.password), []byte(v.salt), v.N, v.r, v.p, len(want))
			if err != nil {
				t.Fatalf("Key failed: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("Key = %x, want %x", got, want)
			}
		})
	}
}

func TestLongerKeyExtendsTheSameStream(t *testing.T) {
	// scrypt finishes with PBKDF2 at one iteration, which concatenates
	// blocks, so a longer derivation begins with the shorter one. Asking for
	// more key material never invalidates what a shorter call produced.
	short := key(t, "password", "salt", 32)
	long := key(t, "password", "salt", 64)
	if !bytes.Equal(short, long[:32]) {
		t.Errorf("32-byte key = %x, prefix of the 64-byte one = %x", short, long[:32])
	}
}

func TestKeyIsDeterministic(t *testing.T) {
	if a, b := key(t, "password", "salt", 32), key(t, "password", "salt", 32); !bytes.Equal(a, b) {
		t.Error("two identical derivations disagreed")
	}
}

func TestEveryInputChangesTheKey(t *testing.T) {
	base := key(t, "password", "salt", 32)

	tests := []struct {
		name     string
		password string
		salt     string
		N, r, p  int
	}{
		{"password", "Password", "salt", testN, testR, testP},
		{"salt", "password", "Salt", testN, testR, testP},
		{"N", "password", "salt", testN * 2, testR, testP},
		{"r", "password", "salt", testN, testR + 1, testP},
		// p multiplies work without multiplying memory, but it is still part
		// of the derivation and must change the output.
		{"p", "password", "salt", testN, testR, testP + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Key([]byte(tt.password), []byte(tt.salt), tt.N, tt.r, tt.p, 32)
			if err != nil {
				t.Fatalf("Key failed: %v", err)
			}
			if bytes.Equal(got, base) {
				t.Errorf("changing %s did not change the key", tt.name)
			}
		})
	}
}

func TestKeyRejectsBadKeyLen(t *testing.T) {
	for _, keyLen := range []int{0, -1} {
		_, err := Key([]byte("password"), []byte("salt"), testN, testR, testP, keyLen)
		if !errors.Is(err, ErrInvalidKeyLen) {
			t.Errorf("Key(keyLen=%d) error = %v, want ErrInvalidKeyLen", keyLen, err)
		}
	}
}

func TestZeroKeyLenWouldPanic(t *testing.T) {
	// Why ErrInvalidKeyLen exists. The library underneath does not validate
	// the key length and finishes with a PBKDF2 call that panics on the error
	// the standard library returns for a non-positive one — so a zero that
	// arrived from configuration would take down the process, from a function
	// whose signature promises an error.
	//
	// Asserting the hazard is real below us keeps the guard above from being
	// cargo-culted, and tells us if upstream ever fixes it.
	func() {
		defer func() {
			if recover() == nil {
				t.Error("upstream no longer panics on a zero key length; revisit ErrInvalidKeyLen")
			}
		}()
		_, err := upstream.Key([]byte("password"), []byte("salt"), testN, testR, testP, 0)
		if err != nil {
			t.Errorf("Key failed: %v", err)
		}
	}()

	// And this package turns it into an error instead.
	if _, err := Key([]byte("password"), []byte("salt"), testN, testR, testP, 0); !errors.Is(err, ErrInvalidKeyLen) {
		t.Errorf("this package accepted a zero key length: err = %v", err)
	}
}

func TestKeyRejectsBadCostParameters(t *testing.T) {
	// These are the underlying library's checks, not this package's. What is
	// asserted here is that they still surface as errors rather than panics,
	// and that our key-length guard has not accidentally shadowed them.
	tests := []struct {
		name    string
		N, r, p int
	}{
		{"N below 2", 1, 1, 1},
		{"N zero", 0, 1, 1},
		{"N not a power of two", 15, 1, 1},
		{"r zero", 16, 0, 1},
		{"p zero", 16, 1, 0},
		{"r negative", 16, -1, 1},
		// r·p must stay below 2³⁰.
		{"r*p too large", 16, 1 << 15, 1 << 15},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Key([]byte("password"), []byte("salt"), tt.N, tt.r, tt.p, 32); err == nil {
				t.Error("Key accepted invalid cost parameters")
			}
		})
	}
}

func TestEmptyPasswordAndSaltAreAllowed(t *testing.T) {
	// Neither is a good idea, but scrypt defines both — RFC 7914's first
	// vector uses exactly that — and this package adds no policy on top of
	// the construction.
	if got := key(t, "", "", 32); len(got) != 32 {
		t.Errorf("length = %d, want 32", len(got))
	}
}

func TestMemoryBytes(t *testing.T) {
	tests := []struct {
		N, r int
		want int64
	}{
		{16, 1, 2048},         // the cheap test parameters: 2 KiB
		{1024, 8, 1 << 20},    // 1 MiB
		{16384, 8, 16 << 20},  // RFC 7914's illustration: 16 MiB
		{1 << 20, 8, 1 << 30}, // 1 GiB — the RFC's omitted fourth vector
		// 4 GiB: past what an int holds on a 32-bit build, which is why the
		// return type is int64. Key itself would reject these parameters
		// there, but the figure is still the right one to report.
		{1 << 20, 32, 4 << 30},
	}
	for _, tt := range tests {
		if got := MemoryBytes(tt.N, tt.r); got != tt.want {
			t.Errorf("MemoryBytes(%d, %d) = %d, want %d", tt.N, tt.r, got, tt.want)
		}
	}
}

func TestMemoryBytesScalesWithNAndR(t *testing.T) {
	// 128·N·r should scale linearly in both, and p must not enter into it —
	// the property that makes p the wrong knob for making scrypt harder.
	base := MemoryBytes(testN, testR)
	if got := MemoryBytes(testN*2, testR); got != base*2 {
		t.Errorf("doubling N gave %d, want %d", got, base*2)
	}
	if got := MemoryBytes(testN, testR*2); got != base*2 {
		t.Errorf("doubling r gave %d, want %d", got, base*2)
	}
	if base != 128*testN*testR {
		t.Errorf("MemoryBytes = %d, want %d", base, 128*testN*testR)
	}
}
