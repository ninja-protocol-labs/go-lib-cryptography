package bls12381poseidon2

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// On known answers, and what they are worth here.
//
// Every byte hash in this module checks its output against an
// implementation other than the one being wrapped. That is not possible
// here: gnark-crypto's parameterisation is its own, no other
// implementation of exactly it is available, and gnark publishes no
// vectors — its own tests are property tests.
//
// So the constants below are recorded from this package's own output, and
// are labelled as that rather than dressed up as vectors. They still earn
// their place: they fail if the byte order flips, if elements are absorbed
// in the wrong order, or if an upstream parameter changes under us. What
// they cannot do is tell us the construction is correct. The structural
// tests further down are what carry weight.
const (
	recordedHashOfOne      = "5dba32f849dc767eeb4429b440b32c775d970a269ba70e821ff6e17b9254c9e4"
	recordedHashOfOneTwo   = "0ee043427202d0231469ed27ea4e3c7f0a31530c6e90c8fe971a1a25da9db4d9"
	recordedCompressOneTwo = "23927976918cacff4850f47a852748216d73f6f4582093316723fc4481b6fb5f"
)

// el returns n as one canonical big-endian field element.
func el(t *testing.T, n int64) []byte {
	t.Helper()
	var e fr.Element
	e.SetInt64(n)
	b := e.Bytes()
	return b[:]
}

// hash is Hash with the error checked, for the cases that are not about
// the error.
func hash(t *testing.T, elems ...[]byte) *Digest {
	t.Helper()
	d, err := Hash(elems...)
	require.NoError(t, err)
	return d
}

// beBytes renders n as ElementLen big-endian bytes, whether or not it is
// below the modulus.
func beBytes(t *testing.T, n *big.Int) []byte {
	t.Helper()
	b := make([]byte, ElementLen)
	n.FillBytes(b)
	return b
}

func TestHashMatchesTheRecordedOutput(t *testing.T) {
	// See the note at the top of this file on what these are and are not.
	one, two := el(t, 1), el(t, 2)

	assert.Equal(t, recordedHashOfOne, hash(t, one).String())
	assert.Equal(t, recordedHashOfOneTwo, hash(t, one, two).String())
}

func TestHashIsDeterministic(t *testing.T) {
	one, two := el(t, 1), el(t, 2)

	assert.True(t, hash(t, one).Equal(hash(t, one)))
	assert.False(t, hash(t, one, two).Equal(hash(t, one)),
		"hashing one element and two gave the same digest")
}

func TestOrderMatters(t *testing.T) {
	one, two := el(t, 1), el(t, 2)

	assert.False(t, hash(t, one, two).Equal(hash(t, two, one)),
		"Hash is order-independent; it must not be")
}

func TestEveryElementAffectsTheDigest(t *testing.T) {
	base := hash(t, el(t, 1), el(t, 2), el(t, 3))

	for i, replaced := range [][][]byte{
		{el(t, 9), el(t, 2), el(t, 3)},
		{el(t, 1), el(t, 9), el(t, 3)},
		{el(t, 1), el(t, 2), el(t, 9)},
	} {
		assert.False(t, hash(t, replaced...).Equal(base),
			"changing element %d did not change the digest", i)
	}
}

func TestStreamingAgreesWithOneShot(t *testing.T) {
	one, two, three := el(t, 1), el(t, 2), el(t, 3)

	h := New()
	require.NoError(t, h.Write(one))
	require.NoError(t, h.Write(two, three))

	got, err := h.Sum()
	require.NoError(t, err)
	assert.True(t, got.Equal(hash(t, one, two, three)))
}

func TestResetStartsOver(t *testing.T) {
	one, two := el(t, 1), el(t, 2)

	h := New()
	require.NoError(t, h.Write(el(t, 99)))
	h.Reset()

	_, err := h.Sum()
	assert.ErrorIs(t, err, ErrNoInput, "Reset left the write count behind")

	require.NoError(t, h.Write(one, two))
	got, err := h.Sum()
	require.NoError(t, err)
	assert.True(t, got.Equal(hash(t, one, two)))
}

func TestEmptyInputIsRejected(t *testing.T) {
	// The library underneath returns its unchanged initial state, which is
	// a valid-looking digest indistinguishable from an uninitialised value.
	_, err := Hash()
	assert.ErrorIs(t, err, ErrNoInput)

	_, err = New().Sum()
	assert.ErrorIs(t, err, ErrNoInput)
}

// 32 bytes has more values than the field has elements. Reducing an
// out-of-range one instead of rejecting it would map two distinct inputs
// to the same digest.
func TestNonCanonicalElementsAreRejectedNotReduced(t *testing.T) {
	r := fr.Modulus()

	tests := []struct {
		name string
		in   []byte
	}{
		{"the modulus itself", beBytes(t, r)},
		{"modulus plus one", beBytes(t, new(big.Int).Add(r, big.NewInt(1)))},
		{"all 0xff", beBytes(t, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 8*ElementLen), big.NewInt(1)))},
		{"nil", nil},
		{"empty", []byte{}},
		{"short", make([]byte, ElementLen-1)},
		{"long", make([]byte, ElementLen+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Hash(tt.in)
			assert.ErrorIs(t, err, ErrNotCanonical)

			_, err = Compress(tt.in, el(t, 1))
			assert.ErrorIs(t, err, ErrNotCanonical)

			assert.ErrorIs(t, New().Write(tt.in), ErrNotCanonical)

			_, err = DigestFromBytes(tt.in)
			assert.ErrorIs(t, err, ErrNotCanonical)
		})
	}

	// And the reduction that must not be happening: r+1 reduces to 1, so
	// if it were reduced these two would agree.
	reduced := hash(t, el(t, 1))
	_, err := Hash(beBytes(t, new(big.Int).Add(r, big.NewInt(1))))
	require.ErrorIs(t, err, ErrNotCanonical)
	assert.False(t, reduced.IsZero())
}

// Write validates the whole batch before absorbing any of it, so a
// rejected call must leave the hasher exactly as it was.
func TestRejectedWriteLeavesTheHasherUsable(t *testing.T) {
	one, two := el(t, 1), el(t, 2)
	bad := beBytes(t, fr.Modulus())

	h := New()
	require.NoError(t, h.Write(one))
	assert.ErrorIs(t, h.Write(two, bad), ErrNotCanonical)
	require.NoError(t, h.Write(two))

	got, err := h.Sum()
	require.NoError(t, err)
	assert.True(t, got.Equal(hash(t, one, two)),
		"the rejected write absorbed something")
}

func TestDigestFromBytesRoundTrip(t *testing.T) {
	d := hash(t, el(t, 1), el(t, 2))
	b := d.Bytes()

	same, err := DigestFromBytes(b[:])
	require.NoError(t, err)
	assert.True(t, d.Equal(same))
	assert.Equal(t, d.String(), same.String())
}

// A digest is itself a field element, so it can be fed straight back in —
// which is what building a Merkle tree does at every level.
func TestADigestIsAValidInput(t *testing.T) {
	child := hash(t, el(t, 1))
	b := child.Bytes()

	parent, err := Compress(b[:], b[:])
	require.NoError(t, err)
	assert.False(t, parent.IsZero())
	assert.False(t, parent.Equal(child))
}

func TestDigestEqual(t *testing.T) {
	a, b := hash(t, el(t, 1)), hash(t, el(t, 2))

	assert.True(t, a.Equal(a))
	assert.False(t, a.Equal(b))
	assert.False(t, a.Equal(nil))
}

func TestDigestIsZero(t *testing.T) {
	var uninit Digest
	var nilDigest *Digest

	assert.True(t, uninit.IsZero())
	assert.True(t, nilDigest.IsZero())
	assert.False(t, hash(t, el(t, 1)).IsZero())

	// Zero is a canonical field element, so it parses; only IsZero flags it.
	zero, err := DigestFromBytes(make([]byte, ElementLen))
	require.NoError(t, err)
	assert.True(t, zero.IsZero())
}

func TestDigestString(t *testing.T) {
	d := hash(t, el(t, 1))
	b := d.Bytes()

	assert.Equal(t, hex.EncodeToString(b[:]), d.String())
	assert.Equal(t, recordedHashOfOne, d.String())
}

// Bytes returns a copy; mutating it must not reach the digest.
func TestDigestBytesIsACopy(t *testing.T) {
	d := hash(t, el(t, 1))

	got := d.Bytes()
	got[0] ^= 0xff

	assert.Equal(t, recordedHashOfOne, d.String())
}

func TestConstants(t *testing.T) {
	assert.Equal(t, fr.Bytes, ElementLen)
	assert.Equal(t, ElementLen, Size)
	assert.Equal(t, ElementLen, BlockSize)
}

// Compress is one permutation call; Hash of the same two elements is
// Compress(Compress(IV, a), b). Conflating them silently produces a
// Merkle tree no verifier agrees with.
func TestCompressIsNotHashOfTwo(t *testing.T) {
	left, right := el(t, 1), el(t, 2)

	got, err := Compress(left, right)
	require.NoError(t, err)

	assert.Equal(t, recordedCompressOneTwo, got.String())
	assert.False(t, got.Equal(hash(t, left, right)),
		"Compress and Hash agreed; they are different functions")
}

// A Merkle tree depends on the two children not being interchangeable.
func TestCompressIsNotSymmetric(t *testing.T) {
	left, right := el(t, 7), el(t, 11)

	a, err := Compress(left, right)
	require.NoError(t, err)
	b, err := Compress(right, left)
	require.NoError(t, err)

	assert.False(t, a.Equal(b), "Compress(a, b) == Compress(b, a)")
}

// Sum reads this hash without advancing it, so it can be called as often
// as you like and writing more continues from the last Write.
func TestSumIsAPureRead(t *testing.T) {
	one, two := el(t, 1), el(t, 2)

	h := New()
	require.NoError(t, h.Write(one))

	first, err := h.Sum()
	require.NoError(t, err)
	again, err := h.Sum()
	require.NoError(t, err)
	assert.True(t, first.Equal(again), "Sum advanced the hash")

	require.NoError(t, h.Write(two))
	second, err := h.Sum()
	require.NoError(t, err)
	assert.True(t, second.Equal(hash(t, one, two)))
}
