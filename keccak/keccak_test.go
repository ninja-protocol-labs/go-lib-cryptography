package keccak

import (
	"bytes"
	"encoding/hex"
	"hash"
	"testing"

	"github.com/ninja-protocol-labs/go-lib-cryptography/sha3"
)

// testMsg is "abc", the input the sha2 and sha3 packages hash too, so the
// vectors here line up with theirs for comparison.
var testMsg = []byte("abc")

// Expected digests, produced with OpenSSL's KECCAK-256/KECCAK-512 rather
// than with the library being wrapped. emptyKeccak256 is the value
// Ethereum uses as the hash of empty code, so it is a vector anyone
// working on that side will recognize on sight.
const (
	abcKeccak256   = "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
	abcKeccak512   = "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96"
	emptyKeccak256 = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	emptyKeccak512 = "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e"
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
	block int
	sum   func([]byte) []byte
	new   func() hash.Hash
	abc   string
	empty string
}

func digests() []digest {
	return []digest{
		{"Keccak-256", Size256, BlockSize256, func(b []byte) []byte { d := Sum256(b); return d[:] }, New256, abcKeccak256, emptyKeccak256},
		{"Keccak-512", Size512, BlockSize512, func(b []byte) []byte { d := Sum512(b); return d[:] }, New512, abcKeccak512, emptyKeccak512},
	}
}

func TestSumMatchesKnownAnswer(t *testing.T) {
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			want := mustDecodeHex(t, d.abc)
			if got := d.sum(testMsg); !bytes.Equal(got, want) {
				t.Errorf("Sum(%q) = %x, want %x", testMsg, got, want)
			}
			if len(want) != d.size {
				t.Errorf("vector length = %d, want %d", len(want), d.size)
			}
		})
	}
}

func TestSumOfEmptyInput(t *testing.T) {
	// Nothing but padding — and for Keccak-256 the single most recognized
	// vector there is, since Ethereum stores it as the code hash of every
	// account without code.
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			want := mustDecodeHex(t, d.empty)
			if got := d.sum(nil); !bytes.Equal(got, want) {
				t.Errorf("Sum(nil) = %x, want %x", got, want)
			}
			if got := d.sum([]byte{}); !bytes.Equal(got, want) {
				t.Errorf("Sum(empty slice) = %x, want %x", got, want)
			}
		})
	}
}

func TestStreamingAgreesWithOneShot(t *testing.T) {
	// Sum256/Sum512 are this package's own, built on top of the streaming
	// hash upstream provides — so unlike the other hash packages here,
	// this is checking code we wrote, not just a re-export.
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			h := d.new()
			if h.Size() != d.size {
				t.Errorf("New().Size() = %d, want %d", h.Size(), d.size)
			}
			if h.BlockSize() != d.block {
				t.Errorf("New().BlockSize() = %d, want %d", h.BlockSize(), d.block)
			}
			h.Write(testMsg[:1])
			h.Write(testMsg[1:])
			if got, want := h.Sum(nil), d.sum(testMsg); !bytes.Equal(got, want) {
				t.Errorf("streaming = %x, one-shot = %x", got, want)
			}
		})
	}
}

func TestSumDoesNotAliasOrOverrun(t *testing.T) {
	// Sum256 sums into out[:0], relying on append not reallocating when
	// the capacity is exactly the digest length. If that ever stopped
	// holding, the returned array would be zero instead of the digest.
	got := Sum256(testMsg)
	if got == ([Size256]byte{}) {
		t.Fatal("Sum256 returned an all-zero array")
	}
	// Two calls must not share state.
	if Sum256(testMsg) != got {
		t.Error("two calls to Sum256 disagreed")
	}
}

func TestStreamingResetIsReusable(t *testing.T) {
	for _, d := range digests() {
		t.Run(d.name, func(t *testing.T) {
			h := d.new()
			h.Write([]byte("something else entirely"))
			h.Reset()
			h.Write(testMsg)
			if got, want := h.Sum(nil), d.sum(testMsg); !bytes.Equal(got, want) {
				t.Errorf("after Reset = %x, want %x", got, want)
			}
		})
	}
}

func TestKeccakIsNotSHA3(t *testing.T) {
	// The whole reason this package exists. Same permutation, same rate,
	// same digest length, one different padding byte — and so completely
	// different output. Nothing about a mix-up produces a type error or a
	// length error, which is why it is asserted here.
	k := Sum256(testMsg)
	s := sha3.Sum256(testMsg)
	if k == s {
		t.Error("Keccak-256 and SHA3-256 produced the same digest")
	}

	if k512, s512 := Sum512(testMsg), sha3.Sum512(testMsg); k512 == s512 {
		t.Error("Keccak-512 and SHA3-512 produced the same digest")
	}
}

func TestRatesMatchSHA3(t *testing.T) {
	// The padding byte is the only difference between the two packages,
	// so the sponge parameters must be identical at matching lengths.
	if BlockSize256 != sha3.BlockSize256 {
		t.Errorf("BlockSize256 = %d, sha3's = %d", BlockSize256, sha3.BlockSize256)
	}
	if BlockSize512 != sha3.BlockSize512 {
		t.Errorf("BlockSize512 = %d, sha3's = %d", BlockSize512, sha3.BlockSize512)
	}
}
