package bn254poseidon2

import (
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// On known answers, and what they are worth here.
//
// Every byte-hash package in this module checks its output against an
// implementation other than the one being wrapped. That is not possible
// here. gnark-crypto's Poseidon2 is its own parameterisation, and the other
// implementations people call "Poseidon" — circomlib, Polygon, StarkNet —
// are different functions with different constants, so none of them can
// serve as a cross-check. gnark publishes no vectors of its own either.
//
// So the constants below are recorded from this package's own output, and
// are labelled as that rather than dressed up as vectors. They still earn
// their place: they fail if the byte order flips, if elements are absorbed
// in the wrong order, or if an upstream parameter changes under us. What
// they cannot do is tell us gnark's Poseidon2 is correct. The structural
// tests further down are what carry real weight.
const (
	recordedCompressOneTwo = "02e7529d93e1a7ae526147c2ee72588aee90e6a7c3e361de6daa6be045c6f530"
	recordedSumOfOne       = "1ae0efd28c01163c0a58440757ef2339affb17836ad3b1fedacabeaab56ca0e2"
	recordedSumOfOneTwo    = "09d2e656ec5144af0711a5528a3af6ebc908d9050b3455edf3b5d0218820875c"
)

// el builds an Element from a small integer, the simplest in-range value.
func el(t *testing.T, n int64) Element {
	t.Helper()
	var e fr.Element
	e.SetInt64(n)
	return Element(e.Bytes())
}

func sum(t *testing.T, elems ...Element) Element {
	t.Helper()
	got, err := Sum(elems...)
	if err != nil {
		t.Fatalf("Sum failed: %v", err)
	}
	return got
}

func compress(t *testing.T, l, r Element) Element {
	t.Helper()
	got, err := Compress(l, r)
	if err != nil {
		t.Fatalf("Compress failed: %v", err)
	}
	return got
}

func hexOf(e Element) string { return hex.EncodeToString(e[:]) }

func TestMatchesTheRecordedOutput(t *testing.T) {
	// See the note at the top of this file on what these are and are not.
	one, two := el(t, 1), el(t, 2)

	if got := hexOf(compress(t, one, two)); got != recordedCompressOneTwo {
		t.Errorf("Compress(1, 2) = %s, recorded %s", got, recordedCompressOneTwo)
	}
	if got := hexOf(sum(t, one)); got != recordedSumOfOne {
		t.Errorf("Sum(1) = %s, recorded %s", got, recordedSumOfOne)
	}
	if got := hexOf(sum(t, one, two)); got != recordedSumOfOneTwo {
		t.Errorf("Sum(1, 2) = %s, recorded %s", got, recordedSumOfOneTwo)
	}
}

func TestCompressIsNotSumOfTwo(t *testing.T) {
	// The difference from bn254mimc, and the one most likely to be assumed
	// away: Sum starts from the all-zero initial state, so Sum(a, b) is
	// Compress(Compress(IV, a), b), not Compress(a, b). A Merkle tree built
	// with the wrong one still produces digests — just not the ones any
	// verifier expects.
	one, two := el(t, 1), el(t, 2)
	if compress(t, one, two) == sum(t, one, two) {
		t.Error("Compress(a, b) == Sum(a, b); the Merkle-Damgard IV is not being applied")
	}

	// Sum is exactly that chain, which pins the relationship rather than
	// just asserting they differ.
	var zero Element
	want := compress(t, compress(t, zero, one), two)
	if got := sum(t, one, two); got != want {
		t.Errorf("Sum(1, 2) = %s, Compress(Compress(0, 1), 2) = %s", hexOf(got), hexOf(want))
	}
}

func TestCompressIsNotSymmetric(t *testing.T) {
	// A Merkle tree depends on left and right being distinguishable.
	one, two := el(t, 1), el(t, 2)
	if compress(t, one, two) == compress(t, two, one) {
		t.Error("Compress(a, b) == Compress(b, a)")
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

func TestStreamingAgreesWithOneShot(t *testing.T) {
	elems := []Element{el(t, 1), el(t, 2), el(t, 3), el(t, 4)}

	d := New()
	// Uneven batches, so the batching itself cannot matter.
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

func TestSumIsAPureRead(t *testing.T) {
	// Documented on Digest.Sum, and the opposite of bn254mimc's, which
	// folds state on every call. Here Sum can be taken repeatedly and
	// writing afterwards continues from the same place.
	a, b := el(t, 1), el(t, 2)

	d := New()
	if err := d.Write(a); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	first, err := d.Sum()
	if err != nil {
		t.Fatalf("Sum failed: %v", err)
	}
	again, err := d.Sum()
	if err != nil {
		t.Fatalf("Sum failed: %v", err)
	}
	if first != again {
		t.Error("two consecutive Sums disagreed; Sum is not a pure read")
	}

	if err := d.Write(b); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	second, err := d.Sum()
	if err != nil {
		t.Fatalf("Sum failed: %v", err)
	}
	if want := sum(t, a, b); second != want {
		t.Errorf("after writing more = %s, want the digest of both: %s", hexOf(second), hexOf(want))
	}
}

func TestResetStartsOver(t *testing.T) {
	d := New()
	if err := d.Write(el(t, 42)); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	d.Reset()

	// Reset must clear the written counter too, or Sum would report the
	// all-zero initial state instead of ErrNoInput.
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
	// Why ErrNoInput exists: the construction underneath returns its
	// initial state, 32 zero bytes, which is a valid-looking digest
	// indistinguishable from an uninitialised value.
	if _, err := Sum(); !errors.Is(err, ErrNoInput) {
		t.Errorf("Sum() error = %v, want ErrNoInput", err)
	}
	if _, err := New().Sum(); !errors.Is(err, ErrNoInput) {
		t.Errorf("New().Sum() error = %v, want ErrNoInput", err)
	}
}

// beBytes renders a big.Int as 32 big-endian bytes.
func beBytes(t *testing.T, n *big.Int) Element {
	t.Helper()
	var out Element
	n.FillBytes(out[:])
	return out
}

func TestNonCanonicalElementsAreRejectedNotReduced(t *testing.T) {
	r := fr.Modulus()

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
			if _, err := Compress(tt.in, el(t, 1)); !errors.Is(err, ErrNotCanonical) {
				t.Errorf("Compress(bad, ok) error = %v, want ErrNotCanonical", err)
			}
			if _, err := Compress(el(t, 1), tt.in); !errors.Is(err, ErrNotCanonical) {
				t.Errorf("Compress(ok, bad) error = %v, want ErrNotCanonical", err)
			}
			if _, err := FromBytes(tt.in[:]); !errors.Is(err, ErrNotCanonical) {
				t.Errorf("FromBytes error = %v, want ErrNotCanonical", err)
			}
		})
	}

	// r-1 is the largest in-range value and must be accepted.
	if _, err := Sum(beBytes(t, new(big.Int).Sub(r, big.NewInt(1)))); err != nil {
		t.Errorf("Sum rejected r-1: %v", err)
	}
}

func TestRejectedWriteLeavesTheDigestUsable(t *testing.T) {
	// Validation happens for the whole batch before anything is absorbed.
	// That matters more here than tidiness: the construction underneath
	// assigns nil to its running state when a compression fails, which
	// would leave the digest permanently broken.
	bad := beBytes(t, fr.Modulus())
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
		t.Fatalf("Sum failed after a rejected Write: %v", err)
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
	// Compress requires a width-2 permutation; if this ever changed,
	// Compress would start returning an error instead of a digest.
	if Width != 2 {
		t.Errorf("Width = %d, want 2", Width)
	}
}
