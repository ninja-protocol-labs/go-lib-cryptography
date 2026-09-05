package argon2

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	upstream "golang.org/x/crypto/argon2"
)

// Known answers produced with OpenSSL's ARGON2ID and ARGON2I KDFs, an
// implementation independent of the Go library this package wraps —
// deriving with x/crypto and comparing against x/crypto would only show
// the wrapper is self-consistent.
//
// RFC 9106's own vectors cannot be reproduced through this API: they use a
// non-empty secret key and associated data, which x/crypto's exported
// functions do not accept.
var vectors = []struct {
	name    string
	fn      func(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) ([]byte, error)
	time    uint32
	memory  uint32
	threads uint8
	want    string
}{
	{
		"Argon2id t=2 m=64MiB p=1", IDKey, 2, 65536, 1,
		"09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7",
	},
	{
		"Argon2i t=2 m=64MiB p=1", IKey, 2, 65536, 1,
		"c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0",
	},
	{
		// p=4, the only vector here that exercises multiple lanes, and a
		// 64-byte output rather than 32.
		"Argon2id t=1 m=4MiB p=4 len=64", IDKey, 1, 4096, 4,
		"b5b545fdef4485c0a4454e95aa4dc167c8cec0f357c264f6800d4f194949fa213" +
			"476a00ae798f3aa8028141e4b60cff8a3d4c70ccc44ce9e470b3d450851f04e",
	},
	{
		// The smallest memory worth testing: 32 KiB, which is also the
		// floor 8·threads would impose at p=4.
		"Argon2id t=3 m=32KiB p=1", IDKey, 3, 32, 1,
		"6d4c5fa26a057c23e3a4f72ae34c64e71398c851f2c79464e3e670ed41b543f9",
	},
}

var (
	testPassword = []byte("password")
	testSalt     = []byte("somesalt")
)

// Cheap parameters for the tests that are about behaviour rather than
// known answers, so the suite stays fast: one pass over 32 KiB.
const (
	testTime    = 1
	testMemory  = 32
	testThreads = 1
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad test vector %q: %v", s, err)
	}
	return b
}

func idKey(t *testing.T, password, salt []byte, keyLen uint32) []byte {
	t.Helper()
	k, err := IDKey(password, salt, testTime, testMemory, testThreads, keyLen)
	if err != nil {
		t.Fatalf("IDKey failed: %v", err)
	}
	return k
}

func TestKeyMatchesKnownAnswers(t *testing.T) {
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			want := mustDecodeHex(t, v.want)
			got, err := v.fn(testPassword, testSalt, v.time, v.memory, v.threads, uint32(len(want)))
			if err != nil {
				t.Fatalf("derivation failed: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("got %x, want %x", got, want)
			}
		})
	}
}

func TestVariantsAreDomainSeparated(t *testing.T) {
	// Argon2i and Argon2id differ only in how they choose reference blocks,
	// and the variant is bound into the initial hash. Same inputs, same
	// parameters, different key — which is the whole reason this package
	// refuses to offer a function called Key.
	id, err := IDKey(testPassword, testSalt, testTime, testMemory, testThreads, 32)
	if err != nil {
		t.Fatalf("IDKey failed: %v", err)
	}
	i, err := IKey(testPassword, testSalt, testTime, testMemory, testThreads, 32)
	if err != nil {
		t.Fatalf("IKey failed: %v", err)
	}
	if bytes.Equal(id, i) {
		t.Error("Argon2id and Argon2i produced the same key")
	}
}

func TestKeyIsDeterministic(t *testing.T) {
	a := idKey(t, testPassword, testSalt, 32)
	b := idKey(t, testPassword, testSalt, 32)
	if !bytes.Equal(a, b) {
		t.Error("two identical derivations disagreed")
	}
}

func TestEveryInputChangesTheKey(t *testing.T) {
	base := idKey(t, testPassword, testSalt, 32)

	tests := []struct {
		name     string
		password []byte
		salt     []byte
		time     uint32
		memory   uint32
		threads  uint8
	}{
		{"password", []byte("Password"), testSalt, testTime, testMemory, testThreads},
		{"salt", testPassword, []byte("othersalt"), testTime, testMemory, testThreads},
		{"time", testPassword, testSalt, testTime + 1, testMemory, testThreads},
		{"memory", testPassword, testSalt, testTime, testMemory * 2, testThreads},
		// threads multiplies work without multiplying memory, but it is
		// bound into the derivation, so it is part of the stored parameter
		// set rather than a per-machine performance dial.
		{"threads", testPassword, testSalt, testTime, testMemory, testThreads + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IDKey(tt.password, tt.salt, tt.time, tt.memory, tt.threads, 32)
			if err != nil {
				t.Fatalf("IDKey failed: %v", err)
			}
			if bytes.Equal(got, base) {
				t.Errorf("changing the %s did not change the key", tt.name)
			}
		})
	}
}

func TestKeyLenChangesTheWholeKey(t *testing.T) {
	// Unlike pbkdf2, scrypt and BLAKE3, Argon2's output length is bound
	// into the initial hash and into its final BLAKE2b step, so a longer
	// derivation is not an extension of a shorter one. A caller who assumed
	// the prefix property would silently get unrelated key material.
	short := idKey(t, testPassword, testSalt, 32)
	long := idKey(t, testPassword, testSalt, 64)
	if bytes.Equal(short, long[:32]) {
		t.Error("a 32-byte key is a prefix of a 64-byte one; the length is not bound in")
	}
}

func TestRequestedMemoryIsBoundInNotTheRoundedOne(t *testing.T) {
	// The trap documented on MemoryBytes. m' = 4·p·floor(m/4·p) is what
	// gets allocated, but the requested m is what the derivation binds — so
	// two values that allocate identically still produce different keys.
	// Normalising a stored parameter to its effective value would break
	// re-derivation, silently.
	const threads = 4
	const requested, rounded = 1000, 992 // 4·4·floor(1000/16) = 992

	if a, b := MemoryBytes(requested, threads), MemoryBytes(rounded, threads); a != b {
		t.Fatalf("test premise is wrong: %d and %d allocate %d and %d", requested, rounded, a, b)
	}

	withRequested, err := IDKey(testPassword, testSalt, 1, requested, threads, 32)
	if err != nil {
		t.Fatalf("IDKey failed: %v", err)
	}
	withRounded, err := IDKey(testPassword, testSalt, 1, rounded, threads, 32)
	if err != nil {
		t.Fatalf("IDKey failed: %v", err)
	}
	if bytes.Equal(withRequested, withRounded) {
		t.Error("the rounded and requested memory values produced the same key")
	}
}

func TestRejectsWhatUpstreamWouldPanicOn(t *testing.T) {
	tests := []struct {
		name    string
		time    uint32
		threads uint8
		keyLen  uint32
		want    error
	}{
		{"zero time", 0, testThreads, 32, ErrInvalidTime},
		{"zero threads", testTime, 0, 32, ErrInvalidThreads},
		{"zero key length", testTime, testThreads, 0, ErrInvalidKeyLen},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The library underneath returns no error, so each of these is
			// a panic there. Asserting that keeps the guards above from
			// being cargo-culted, and says so if upstream ever changes.
			func() {
				defer func() {
					if recover() == nil {
						t.Errorf("upstream no longer panics on %s; revisit %v", tt.name, tt.want)
					}
				}()
				upstream.IDKey(testPassword, testSalt, tt.time, testMemory, tt.threads, tt.keyLen)
			}()

			if _, err := IDKey(testPassword, testSalt, tt.time, testMemory, tt.threads, tt.keyLen); !errors.Is(err, tt.want) {
				t.Errorf("IDKey error = %v, want %v", err, tt.want)
			}
			if _, err := IKey(testPassword, testSalt, tt.time, testMemory, tt.threads, tt.keyLen); !errors.Is(err, tt.want) {
				t.Errorf("IKey error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestTinyMemoryIsClampedNotRejected(t *testing.T) {
	// No memory value panics: the library floors it at 8·threads instead.
	// So this must succeed rather than error, and must agree with what
	// MemoryBytes says the floor is.
	got, err := IDKey(testPassword, testSalt, 1, 0, 4, 32)
	if err != nil {
		t.Fatalf("IDKey rejected a zero memory parameter: %v", err)
	}
	if len(got) != 32 {
		t.Errorf("length = %d, want 32", len(got))
	}
	if want := int64(8 * 4 * 1024); MemoryBytes(0, 4) != want {
		t.Errorf("MemoryBytes(0, 4) = %d, want the %d floor", MemoryBytes(0, 4), want)
	}
}

func TestEmptyPasswordAndSaltAreAllowed(t *testing.T) {
	// Neither is a good idea — RFC 9106 requires a salt of at least 8
	// bytes — but this package adds no policy the construction does not
	// have, matching the library underneath and other implementations.
	if got := idKey(t, nil, nil, 32); len(got) != 32 {
		t.Errorf("length = %d, want 32", len(got))
	}
}

func TestMemoryBytes(t *testing.T) {
	tests := []struct {
		name    string
		memory  uint32
		threads uint8
		want    int64
	}{
		{"exact multiple", 65536, 1, 64 << 20},
		{"exact multiple, p=4", 4096, 4, 4 << 20},
		{"rounded down", 1000, 4, 992 * 1024},
		{"rounded down, p=1", 1001, 1, 1000 * 1024},
		{"below the floor", 1, 1, 8 * 1024},
		{"below the floor, p=4", 0, 4, 32 * 1024},
		// Past 2³² bytes, which is why the return type is int64.
		{"beyond a uint32 of bytes", 1 << 22, 1, 4 << 30},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MemoryBytes(tt.memory, tt.threads); got != tt.want {
				t.Errorf("MemoryBytes(%d, %d) = %d, want %d", tt.memory, tt.threads, got, tt.want)
			}
		})
	}
}
