package pbkdf2

import (
	stdlib "crypto/pbkdf2"
	"crypto/sha1"
	"encoding/hex"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ninja-protocol-labs/go-lib-cryptography/sha2"
)

// The RFC 6070 vectors for PBKDF2-HMAC-SHA1, plus SHA-256 and SHA-512
// cases. Regenerated with Python's hashlib and cross-checked against
// OpenSSL's PBKDF2 KDF, rather than taken from the standard library this
// package wraps.
//
// The c=16777216 case from RFC 6070 is omitted: it is minutes of work for
// no coverage the c=4096 case does not already give.
var vectors = []struct {
	name     string
	h        func() hash.Hash
	password string
	salt     string
	iter     int
	keyLen   int
	want     string
}{
	{"sha1/c=1", sha1.New, "password", "salt", 1, 20,
		"0c60c80f961f0e71f3a9b524af6012062fe037a6"},
	{"sha1/c=2", sha1.New, "password", "salt", 2, 20,
		"ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
	{"sha1/c=4096", sha1.New, "password", "salt", 4096, 20,
		"4b007901b765489abead49d926f721d065a429c1"},
	// Password and salt both longer than SHA-1's 64-byte block, and a key
	// length that is not a whole number of hash outputs.
	{"sha1/long inputs", sha1.New,
		"passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25,
		"3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"},
	// Embedded NUL bytes, which a C implementation that treats the
	// password as a C string would truncate at.
	{"sha1/embedded NULs", sha1.New, "pass\x00word", "sa\x00lt", 4096, 16,
		"56fa6aa75548099dcc37d7f03425e0c3"},

	{"sha256/c=1", sha2.New256, "password", "salt", 1, 32,
		"120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
	{"sha256/c=4096", sha2.New256, "password", "salt", 4096, 32,
		"c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
	{"sha512/c=4096", sha2.New512, "password", "salt", 4096, 64,
		"d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5" +
			"143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5"},
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err, "bad test vector %q", s)
	return b
}

func TestKeyMatchesKnownAnswers(t *testing.T) {
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			got, err := Key(v.h, []byte(v.password), []byte(v.salt), v.iter, v.keyLen)
			require.NoError(t, err)

			assert.Equal(t, mustDecodeHex(t, v.want), got)
			assert.Len(t, got, v.keyLen)
		})
	}
}

func TestLongerKeyExtendsTheSameStream(t *testing.T) {
	// PBKDF2 concatenates blocks T₁‖T₂‖…, so a longer derivation begins
	// with the shorter one. Asking for more key material never invalidates
	// what a shorter call produced.
	short, err := Key(sha2.New256, []byte("password"), []byte("salt"), 4096, 32)
	require.NoError(t, err)
	long, err := Key(sha2.New256, []byte("password"), []byte("salt"), 4096, 64)
	require.NoError(t, err)

	assert.Equal(t, short, long[:32])
}

func TestEveryInputChangesTheKey(t *testing.T) {
	base, err := Key(sha2.New256, []byte("password"), []byte("salt"), 1000, 32)
	require.NoError(t, err)

	tests := []struct {
		name     string
		h        func() hash.Hash
		password string
		salt     string
		iter     int
	}{
		{"password", sha2.New256, "Password", "salt", 1000},
		{"salt", sha2.New256, "password", "Salt", 1000},
		{"iterations", sha2.New256, "password", "salt", 1001},
		// The PRF is part of the derivation, so the same password, salt
		// and count under a different hash must not collide.
		{"hash", sha2.New512, "password", "salt", 1000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Key(tt.h, []byte(tt.password), []byte(tt.salt), tt.iter, 32)
			require.NoError(t, err)

			assert.NotEqual(t, base, got, "changing the %s did not change the key", tt.name)
		})
	}
}

func TestKeyIsDeterministic(t *testing.T) {
	a, err := Key(sha2.New256, []byte("password"), []byte("salt"), 1000, 32)
	require.NoError(t, err)
	b, err := Key(sha2.New256, []byte("password"), []byte("salt"), 1000, 32)
	require.NoError(t, err)

	assert.Equal(t, a, b, "two identical derivations disagreed")
}

func TestKeyRejectsBadParameters(t *testing.T) {
	tests := []struct {
		name   string
		iter   int
		keyLen int
		want   error
	}{
		{"zero iterations", 0, 32, ErrInvalidIterations},
		{"negative iterations", -1, 32, ErrInvalidIterations},
		{"zero key length", 1000, 0, ErrInvalidKeyLen},
		{"negative key length", 1000, -1, ErrInvalidKeyLen},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Key(sha2.New256, []byte("password"), []byte("salt"), tt.iter, tt.keyLen)
			assert.ErrorIs(t, err, tt.want)
		})
	}
}

func TestZeroIterationsWouldSilentlyDegrade(t *testing.T) {
	// Why ErrInvalidIterations exists. The standard library does not
	// check the count: its loop runs from 2 to iter, so zero and one
	// produce the same key, and a count that arrived as zero from a config
	// file would give the weakest possible derivation with nothing
	// failing. This asserts that hazard is real in the layer below, so the
	// check above is not cargo-culted — and that our Key refuses it.
	weakest, err := stdlib.Key(sha2.New256, "password", []byte("salt"), 1, 32)
	require.NoError(t, err)
	degraded, err := stdlib.Key(sha2.New256, "password", []byte("salt"), 0, 32)
	require.NoError(t, err, "the standard library rejected a zero count after all")
	require.Equal(t, weakest, degraded,
		"a zero count no longer collapses to one iteration; revisit ErrInvalidIterations")

	_, err = Key(sha2.New256, []byte("password"), []byte("salt"), 0, 32)
	assert.ErrorIs(t, err, ErrInvalidIterations, "this package accepted a zero count")
}

func TestEmptyPasswordAndSaltAreAllowed(t *testing.T) {
	// Neither is a good idea, but PBKDF2 defines both and this package
	// does not add policy on top of the construction — an empty salt is
	// the caller's mistake to make, and silently rejecting it would
	// diverge from every other implementation.
	got, err := Key(sha2.New256, nil, nil, 1000, 32)
	require.NoError(t, err)
	assert.Len(t, got, 32)
}

// Key takes a []byte password where crypto/pbkdf2 takes a string, so that
// a caller reading a password into a slice can wipe it afterwards and so
// that all three KDFs in this module agree. The conversion has to stay
// faithful, embedded NULs and invalid UTF-8 included — neither is a
// hypothetical, since a password is arbitrary bytes.
func TestPasswordSliceMatchesTheStandardLibrarysString(t *testing.T) {
	for _, password := range []string{"password", "pass\x00word", "\xff\xfe\x00"} {
		t.Run(hex.EncodeToString([]byte(password)), func(t *testing.T) {
			got, err := Key(sha2.New256, []byte(password), []byte("salt"), 100, 32)
			require.NoError(t, err)

			want, err := stdlib.Key(sha2.New256, password, []byte("salt"), 100, 32)
			require.NoError(t, err)

			assert.Equal(t, want, got)
		})
	}
}
