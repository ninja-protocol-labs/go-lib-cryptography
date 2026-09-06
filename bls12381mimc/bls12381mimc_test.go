package bls12381mimc

import (
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// On known answers, and what they are worth here.
//
// Every other hash package in this module checks its output against an
// implementation other than the one being wrapped. That is not possible for
// this one. gnark-crypto's MiMC is its own parameterisation — Miyaguchi-
// Preneel, x⁵, 110 rounds, constants from the seed "seed" — and no other
// implementation of exactly it is available here; circomlib's MiMC and the
// various rollup MiMCs use different parameters and produce different
// digests. gnark publishes no vectors of its own either: its tests are
// property tests.
//
// So the constants below are recorded from this package's own output, and
// are labelled as that rather than dressed up as vectors. They still earn
// their place: they fail if the byte order flips, if elements are absorbed
// in the wrong order, or if an upstream parameter changes under us. What
// they cannot do is tell us gnark's MiMC is correct. The structural tests
// further down are what carry real weight.
const (
	recordedSumOfOne    = "4daf634458df2833f2ce99aa76eff373560f1995545da216fc0fc89a607c14cb"
	recordedSumOfOneTwo = "4fae26ec2db6818bbee540c74843cb5d9714a896b838d92d1cb799a4a44639ba"
)

// el builds an Element from a small integer, the simplest in-range value.
func el(t *testing.T, n int64) Element {
	t.Helper()
	var e fr.Element
	e.SetInt64(n)
	b := e.Bytes()
	return Element(b)
}

func sum(t *testing.T, elems ...Element) Element {
	t.Helper()
	got, err := Sum(elems...)
	if err != nil {
		t.Fatalf("Sum failed: %v", err)
	}
	return got
}

func hexOf(e Element) string { return hex.EncodeToString(e[:]) }

func TestSumMatchesTheRecordedOutput(t *testing.T) {
	// See the note at the top of this file on what these are and are not.
	one, two := el(t, 1), el(t, 2)

	if got := hexOf(sum(t, one)); got != recordedSumOfOne {
		t.Errorf("Sum(1) = %s, recorded %s", got, recordedSumOfOne)
	}
	if got := hexOf(sum(t, one, two)); got != recordedSumOfOneTwo {
		t.Errorf("Sum(1, 2) = %s, recorded %s", got, recordedSumOfOneTwo)
	}
}

func TestSumIsDeterministic(t *testing.T) {
	one, two := el(t, 1), el(t, 2)
	if sum(t, one) != sum(t, one) {
		t.Fatal("Sum is not deterministic")
	}
	if sum(t, one, two) == sum(t, one) {
		t.Error("hashing one element and two elements gave the same digest")
	}
}

func TestOrderMatters(t *testing.T) {
	one, two := el(t, 1), el(t, 2)
	if sum(t, one, two) == sum(t, two, one) {
		t.Error("Sum is order-independent; it must not be")
	}
}

func TestEveryElementAffectsTheDigest(t *testing.T) {
	base := sum(t, el(t, 1), el(t, 2), el(t, 3))
	for i, replaced := range [][]Element{
		{el(t, 9), el(t, 2), el(t, 3)},
		{el(t, 1), el(t, 9), el(t, 3)},
		{el(t, 1), el(t, 2), el(t, 9)},
	} {
		if sum(t, replaced...) == base {
			t.Errorf("changing element %d did not change the digest", i)
		}
	}
}

func TestCompressIsSumOfTwo(t *testing.T) {
	// Compress exists for Merkle trees and is documented as exactly this.
	// If it ever stops being so, every tree built on it changes shape.
	left, right := el(t, 7), el(t, 11)

	got, err := Compress(left, right)
	if err != nil {
		t.Fatalf("Compress failed: %v", err)
	}
	if want := sum(t, left, right); got != want {
		t.Errorf("Compress = %s, Sum of the same two = %s", hexOf(got), hexOf(want))
	}
	// And it is not symmetric — a Merkle tree depends on that.
	other, err := Compress(right, left)
	if err != nil {
		t.Fatalf("Compress failed: %v", err)
	}
	if got == other {
		t.Error("Compress(a, b) == Compress(b, a)")
	}
}

func TestStreamingAgreesWithOneShot(t *testing.T) {
	elems := []Element{el(t, 1), el(t, 2), el(t, 3), el(t, 4)}

	d := New()
	// Written in uneven batches, so the batching itself cannot matter.
	if err := d.Write(elems[0]); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if err := d.Write(elems[1], elems[2]); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if err := d.Write(elems[3]); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	got, err := d.Sum()
	if err != nil {
		t.Fatalf("Sum failed: %v", err)
	}
	if want := sum(t, elems...); got != want {
		t.Errorf("streaming = %s, one-shot = %s", hexOf(got), hexOf(want))
	}
}

func TestSumContinuesTheHash(t *testing.T) {
	// Documented on Digest.Sum: taking a digest does not end the hash, so
	// writing more continues it. Anyone expecting Sum to be a pure read
	// would be surprised, which is why it is pinned here.
	a, b := el(t, 1), el(t, 2)

	d := New()
	if err := d.Write(a); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	first, err := d.Sum()
	if err != nil {
		t.Fatalf("Sum failed: %v", err)
	}
	if want := sum(t, a); first != want {
		t.Errorf("first Sum = %s, want %s", hexOf(first), hexOf(want))
	}

	if err := d.Write(b); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	second, err := d.Sum()
	if err != nil {
		t.Fatalf("Sum failed: %v", err)
	}
	if want := sum(t, a, b); second != want {
		t.Errorf("second Sum = %s, want the digest of both: %s", hexOf(second), hexOf(want))
	}
}

func TestResetStartsOver(t *testing.T) {
	d := New()
	if err := d.Write(el(t, 42)); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	d.Reset()

	// Reset must clear the written counter too, or Sum would report the
	// zero element instead of ErrNoInput.
	if _, err := d.Sum(); !errors.Is(err, ErrNoInput) {
		t.Errorf("Sum after Reset with no writes: err = %v, want ErrNoInput", err)
	}

	if err := d.Write(el(t, 1)); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	got, err := d.Sum()
	if err != nil {
		t.Fatalf("Sum failed: %v", err)
	}
	if want := sum(t, el(t, 1)); got != want {
		t.Errorf("after Reset = %s, want %s", hexOf(got), hexOf(want))
	}
}

func TestEmptyInputIsRejected(t *testing.T) {
	// Why ErrNoInput exists: the layer below returns its initial state, the
	// zero element, which is a valid-looking digest indistinguishable from
	// an uninitialised value.
	if _, err := Sum(); !errors.Is(err, ErrNoInput) {
		t.Errorf("Sum() error = %v, want ErrNoInput", err)
	}
	if _, err := New().Sum(); !errors.Is(err, ErrNoInput) {
		t.Errorf("New().Sum() error = %v, want ErrNoInput", err)
	}
}

// modulus is r, the order of BLS12-381's scalar field.
func modulus() *big.Int { return fr.Modulus() }

// beBytes renders a big.Int as 32 big-endian bytes.
func beBytes(t *testing.T, n *big.Int) Element {
	t.Helper()
	var out Element
	n.FillBytes(out[:])
	return out
}

func TestNonCanonicalElementsAreRejectedNotReduced(t *testing.T) {
	// 32 bytes holds more values than the field has elements. Reducing an
	// out-of-range one would map two distinct inputs to the same digest,
	// so it is refused instead.
	r := modulus()

	tests := []struct {
		name string
		in   Element
	}{
		{"exactly r", beBytes(t, r)},
		{"r + 1", beBytes(t, new(big.Int).Add(r, big.NewInt(1)))},
		{"all 0xff", func() Element {
			var e Element
			for i := range e {
				e[i] = 0xff
			}
			return e
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Sum(tt.in); !errors.Is(err, ErrNotCanonical) {
				t.Errorf("Sum error = %v, want ErrNotCanonical", err)
			}
			if err := New().Write(tt.in); !errors.Is(err, ErrNotCanonical) {
				t.Errorf("Write error = %v, want ErrNotCanonical", err)
			}
			if _, err := FromBytes(tt.in[:]); !errors.Is(err, ErrNotCanonical) {
				t.Errorf("FromBytes error = %v, want ErrNotCanonical", err)
			}
		})
	}

	// r-1 is the largest value that is in range, and must be accepted.
	if _, err := Sum(beBytes(t, new(big.Int).Sub(r, big.NewInt(1)))); err != nil {
		t.Errorf("Sum rejected r-1: %v", err)
	}
}

func TestRejectedWriteLeavesTheDigestUsable(t *testing.T) {
	// Elements are validated as a batch before any is absorbed, so a
	// rejected Write must not leave half its input folded in.
	bad := beBytes(t, modulus())
	one, two := el(t, 1), el(t, 2)

	d := New()
	if err := d.Write(one); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if err := d.Write(two, bad); !errors.Is(err, ErrNotCanonical) {
		t.Fatalf("Write error = %v, want ErrNotCanonical", err)
	}

	got, err := d.Sum()
	if err != nil {
		t.Fatalf("Sum failed: %v", err)
	}
	if want := sum(t, one); got != want {
		t.Errorf("the rejected Write was partially absorbed: got %s, want %s", hexOf(got), hexOf(want))
	}
}

func TestFromBytesRoundTrip(t *testing.T) {
	one := el(t, 1)
	got, err := FromBytes(one[:])
	if err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}
	if got != one {
		t.Errorf("FromBytes round trip = %s, want %s", hexOf(got), hexOf(one))
	}

	for _, b := range [][]byte{nil, make([]byte, ElementLen-1), make([]byte, ElementLen+1)} {
		if _, err := FromBytes(b); !errors.Is(err, ErrNotCanonical) {
			t.Errorf("FromBytes(%d bytes) error = %v, want ErrNotCanonical", len(b), err)
		}
	}
}

func TestConstants(t *testing.T) {
	if ElementLen != 32 {
		t.Errorf("ElementLen = %d, want 32", ElementLen)
	}
	if Size != ElementLen || BlockSize != ElementLen {
		t.Errorf("Size = %d and BlockSize = %d, want both %d", Size, BlockSize, ElementLen)
	}
}
