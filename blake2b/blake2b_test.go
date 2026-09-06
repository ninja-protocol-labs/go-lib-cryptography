package blake2b

import (
	"bytes"
	"encoding/hex"
	"errors"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testMsg is "abc", the input the sha2, sha3 and keccak packages hash too.
var testMsg = []byte("abc")

// testKey is a 32-byte key, 0x01..0x20.
var testKey = func() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}()

// Expected digests, from Python's hashlib — CPython bundles its own
// BLAKE2 reference code, so it is an implementation independent of the
// one being wrapped. The 512-bit unkeyed value was additionally
// cross-checked against OpenSSL's BLAKE2b512.
const (
	abcBlake2b256 = "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
	abcBlake2b384 = "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4"
	abcBlake2b512 = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"

	emptyBlake2b256 = "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
	emptyBlake2b512 = "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"

	keyedBlake2b256 = "280776135edcd561b55edb7abec985333c3995dda3d493de3d29ee5bc45fb333"
	keyedBlake2b512 = "d640a4e02600b99b206c70da1edae39083b36997b508924226af35cca4237f73a05f93784ac56081a21b531a968249caec54e7097236ea898d49604f27b554f4"

	// Non-standard digest lengths, to pin that New(size, ...) is a
	// distinct function per size rather than a truncation.
	abcBlake2b8  = "6b"
	abcBlake2b17 = "658fb5b767c736b82b1a7fa7050454344c"
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad test vector %q: %v", s, err)
	}
	return b
}

type digest struct {
	name  string
	size  int
	sum   func([]byte) []byte
	sumK  func(key, data []byte) ([]byte, error)
	new   func(key []byte) (hash.Hash, error)
	abc   string
	keyed string
}

func digests() []digest {
	return []digest{
		{
			"BLAKE2b-256", Size256,
			func(b []byte) []byte { d := Hash256(b).Bytes(); return d[:] },
			func(k, msg []byte) ([]byte, error) {
				d, err := HashKeyed256(k, msg)
				if err != nil {
					return nil, err
				}
				b := d.Bytes()
				return b[:], nil
			},
			New256, abcBlake2b256, keyedBlake2b256,
		},
		{
			"BLAKE2b-384", Size384,
			func(b []byte) []byte { d := Hash384(b).Bytes(); return d[:] },
			func(k, msg []byte) ([]byte, error) {
				d, err := HashKeyed384(k, msg)
				if err != nil {
					return nil, err
				}
				b := d.Bytes()
				return b[:], nil
			},
			New384, abcBlake2b384, "",
		},
		{
			"BLAKE2b-512", Size512,
			func(b []byte) []byte { d := Hash512(b).Bytes(); return d[:] },
			func(k, msg []byte) ([]byte, error) {
				d, err := HashKeyed512(k, msg)
				if err != nil {
					return nil, err
				}
				b := d.Bytes()
				return b[:], nil
			},
			New512, abcBlake2b512, keyedBlake2b512,
		},
	}
}

func TestSumMatchesKnownAnswer(t *testing.T) {
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			want := mustDecodeHex(t, d.abc)
			if len(want) != d.size {
				t.Fatalf("vector length = %d, want %d", len(want), d.size)
			}
			if got := d.sum(testMsg); !bytes.Equal(got, want) {
				t.Errorf("Sum(%q) = %x, want %x", testMsg, got, want)
			}
		})
	}
}

func TestHashKeyedMatchesKnownAnswer(t *testing.T) {
	for _, d := range digests() {
		if d.keyed == "" {
			continue
		}
		t.Run(d.name, func(t *testing.T) {
			got, err := d.sumK(testKey, testMsg)
			require.NoError(t, err)
			assert.Equal(t, mustDecodeHex(t, d.keyed), got)
		})
	}
}

func TestHashKeyedWithNilKeyEqualsUnkeyed(t *testing.T) {
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			got, err := d.sumK(nil, testMsg)
			require.NoError(t, err)
			assert.Equal(t, d.sum(testMsg), got)
		})
	}
}

func TestKeyChangesTheDigest(t *testing.T) {
	a, err := HashKeyed256(testKey, testMsg)
	require.NoError(t, err)

	other := bytes.Clone(testKey)
	other[0] ^= 0x01
	b, err := HashKeyed256(other, testMsg)
	require.NoError(t, err)

	assert.False(t, a.Equal(b), "two different keys produced the same MAC")
	assert.False(t, a.Equal(Hash256(testMsg)), "the keyed digest equals the unkeyed one")
}

func TestHashOfEmptyInput(t *testing.T) {
	got256 := Hash256(nil).Bytes()
	assert.Equal(t, mustDecodeHex(t, emptyBlake2b256), got256[:])

	got512 := Hash512(nil).Bytes()
	assert.Equal(t, mustDecodeHex(t, emptyBlake2b512), got512[:])

	assert.True(t, Hash256(nil).Equal(Hash256([]byte{})))
}

func TestStreamingAgreesWithOneShot(t *testing.T) {
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			h, err := d.new(nil)
			require.NoError(t, err)
			assert.Equal(t, d.size, h.Size())
			assert.Equal(t, BlockSize, h.BlockSize())

			_, err = h.Write(testMsg[:1])
			require.NoError(t, err)
			_, err = h.Write(testMsg[1:])
			require.NoError(t, err)

			assert.Equal(t, d.sum(testMsg), h.Sum(nil))
		})
	}
}

func TestStreamingResetIsReusable(t *testing.T) {
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			h, err := d.new(testKey)
			require.NoError(t, err)

			_, err = h.Write([]byte("something else entirely"))
			require.NoError(t, err)
			h.Reset()
			_, err = h.Write(testMsg)
			require.NoError(t, err)

			want, err := d.sumK(testKey, testMsg)
			require.NoError(t, err)

			// Reset must keep the key, not drop back to unkeyed.
			assert.Equal(t, want, h.Sum(nil))
		})
	}
}

func TestDigestSizeIsAParameterNotATruncation(t *testing.T) {
	// The headline difference from truncating a hash by hand: the output
	// length is mixed into the initial state, so shorter digests are
	// different functions, not prefixes of longer ones.
	full := Hash512(testMsg).Bytes()

	short := Hash256(testMsg).Bytes()
	assert.NotEqual(t, full[:Size256], short[:])

	mid := Hash384(testMsg).Bytes()
	assert.NotEqual(t, full[:Size384], mid[:])
}

func TestNewAtArbitrarySizes(t *testing.T) {
	// New(32, nil) must agree with Hash256, and odd sizes must match the
	// external vectors — proof that size really is a parameter.
	tests := []struct {
		size int
		want string
	}{
		{1, abcBlake2b8},
		{17, abcBlake2b17},
		{Size256, abcBlake2b256},
	}
	for _, tt := range tests {
		h, err := New(tt.size, nil)
		if err != nil {
			t.Fatalf("New(%d) failed: %v", tt.size, err)
		}
		h.Write(testMsg)
		got := h.Sum(nil)
		if want := mustDecodeHex(t, tt.want); !bytes.Equal(got, want) {
			t.Errorf("New(%d) = %x, want %x", tt.size, got, want)
		}
		if len(got) != tt.size {
			t.Errorf("New(%d) produced %d bytes", tt.size, len(got))
		}
	}
}

func TestNewRejectsBadParameters(t *testing.T) {
	longKey := make([]byte, MaxKeyLen+1)

	for _, size := range []int{0, -1, MaxSize + 1} {
		if _, err := New(size, nil); !errors.Is(err, ErrInvalidSize) {
			t.Errorf("New(%d) error = %v, want ErrInvalidSize", size, err)
		}
	}
	if _, err := New(Size256, longKey); !errors.Is(err, ErrKeyTooLong) {
		t.Errorf("New with an oversized key error = %v, want ErrKeyTooLong", err)
	}
	for _, d := range digests() {
		if _, err := d.new(longKey); !errors.Is(err, ErrKeyTooLong) {
			t.Errorf("%s New with an oversized key error = %v, want ErrKeyTooLong", d.name, err)
		}
		if _, err := d.sumK(longKey, testMsg); !errors.Is(err, ErrKeyTooLong) {
			t.Errorf("%s HashKeyed with an oversized key error = %v, want ErrKeyTooLong", d.name, err)
		}
	}
	// A key of exactly MaxKeyLen is allowed.
	if _, err := New512(make([]byte, MaxKeyLen)); err != nil {
		t.Errorf("New512 rejected a %d-byte key: %v", MaxKeyLen, err)
	}
}
