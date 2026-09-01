package blake2b

import (
	"bytes"
	"encoding/hex"
	"errors"
	"hash"
	"testing"
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
			func(b []byte) []byte { d := Sum256(b); return d[:] },
			func(k, b []byte) ([]byte, error) { d, err := SumKeyed256(k, b); return d[:], err },
			New256, abcBlake2b256, keyedBlake2b256,
		},
		{
			"BLAKE2b-384", Size384,
			func(b []byte) []byte { d := Sum384(b); return d[:] },
			func(k, b []byte) ([]byte, error) { d, err := SumKeyed384(k, b); return d[:], err },
			New384, abcBlake2b384, "",
		},
		{
			"BLAKE2b-512", Size512,
			func(b []byte) []byte { d := Sum512(b); return d[:] },
			func(k, b []byte) ([]byte, error) { d, err := SumKeyed512(k, b); return d[:], err },
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

func TestSumKeyedMatchesKnownAnswer(t *testing.T) {
	for _, d := range digests() {
		if d.keyed == "" {
			continue
		}
		t.Run(d.name, func(t *testing.T) {
			want := mustDecodeHex(t, d.keyed)
			got, err := d.sumK(testKey, testMsg)
			if err != nil {
				t.Fatalf("SumKeyed failed: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("SumKeyed = %x, want %x", got, want)
			}
		})
	}
}

func TestSumKeyedWithNilKeyEqualsUnkeyed(t *testing.T) {
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			got, err := d.sumK(nil, testMsg)
			if err != nil {
				t.Fatalf("SumKeyed failed: %v", err)
			}
			if want := d.sum(testMsg); !bytes.Equal(got, want) {
				t.Errorf("keyed with nil = %x, unkeyed = %x", got, want)
			}
		})
	}
}

func TestKeyChangesTheDigest(t *testing.T) {
	a, err := SumKeyed256(testKey, testMsg)
	if err != nil {
		t.Fatalf("SumKeyed256 failed: %v", err)
	}
	other := bytes.Clone(testKey)
	other[0] ^= 0x01
	b, err := SumKeyed256(other, testMsg)
	if err != nil {
		t.Fatalf("SumKeyed256 failed: %v", err)
	}
	if a == b {
		t.Error("two different keys produced the same MAC")
	}
	if a == Sum256(testMsg) {
		t.Error("the keyed digest equals the unkeyed one")
	}
}

func TestSumOfEmptyInput(t *testing.T) {
	if got, want := Sum256(nil), mustDecodeHex(t, emptyBlake2b256); !bytes.Equal(got[:], want) {
		t.Errorf("Sum256(nil) = %x, want %x", got, want)
	}
	if got, want := Sum512(nil), mustDecodeHex(t, emptyBlake2b512); !bytes.Equal(got[:], want) {
		t.Errorf("Sum512(nil) = %x, want %x", got, want)
	}
	if Sum256(nil) != Sum256([]byte{}) {
		t.Error("Sum256(nil) != Sum256(empty slice)")
	}
}

func TestStreamingAgreesWithOneShot(t *testing.T) {
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			h, err := d.new(nil)
			if err != nil {
				t.Fatalf("New failed: %v", err)
			}
			if h.Size() != d.size {
				t.Errorf("Size() = %d, want %d", h.Size(), d.size)
			}
			if h.BlockSize() != BlockSize {
				t.Errorf("BlockSize() = %d, want %d", h.BlockSize(), BlockSize)
			}
			h.Write(testMsg[:1])
			h.Write(testMsg[1:])
			if got, want := h.Sum(nil), d.sum(testMsg); !bytes.Equal(got, want) {
				t.Errorf("streaming = %x, one-shot = %x", got, want)
			}
		})
	}
}

func TestStreamingResetIsReusable(t *testing.T) {
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			h, err := d.new(testKey)
			if err != nil {
				t.Fatalf("New failed: %v", err)
			}
			h.Write([]byte("something else entirely"))
			h.Reset()
			h.Write(testMsg)

			want, err := d.sumK(testKey, testMsg)
			if err != nil {
				t.Fatalf("SumKeyed failed: %v", err)
			}
			// Reset must keep the key, not drop back to unkeyed.
			if got := h.Sum(nil); !bytes.Equal(got, want) {
				t.Errorf("after Reset = %x, want %x", got, want)
			}
		})
	}
}

func TestDigestSizeIsAParameterNotATruncation(t *testing.T) {
	// The headline difference from truncating a hash by hand: the output
	// length is mixed into the initial state, so shorter digests are
	// different functions, not prefixes of longer ones.
	full := Sum512(testMsg)
	short := Sum256(testMsg)
	if bytes.Equal(short[:], full[:Size256]) {
		t.Error("Sum256 equals the first 32 bytes of Sum512")
	}
	if got, want := Sum384(testMsg), full[:Size384]; bytes.Equal(got[:], want) {
		t.Error("Sum384 equals the first 48 bytes of Sum512")
	}
}

func TestNewAtArbitrarySizes(t *testing.T) {
	// New(32, nil) must agree with Sum256, and odd sizes must match the
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
			t.Errorf("%s SumKeyed with an oversized key error = %v, want ErrKeyTooLong", d.name, err)
		}
	}
	// A key of exactly MaxKeyLen is allowed.
	if _, err := New512(make([]byte, MaxKeyLen)); err != nil {
		t.Errorf("New512 rejected a %d-byte key: %v", MaxKeyLen, err)
	}
}
