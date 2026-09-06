package bls12381

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// The group element types. Each wraps its gnark-crypto counterpart in an
// unexported field rather than aliasing it, so gnark-crypto's field types
// (fp.Element, E2, E12) never appear in this package's API. All three are
// comparable, so == and != work on them directly, as do map keys.

// The standard generators, resolved once at init.
var (
	g1Gen bls12381.G1Affine
	g2Gen bls12381.G2Affine
)

func init() {
	_, _, g1Gen, g2Gen = bls12381.Generators()
}

// G1Point is a point in G1, the curve group over 𝔽p.
type G1Point struct {
	p bls12381.G1Affine
}

// G2Point is a point in G2, the subgroup of the sextic twist over 𝔽p².
type G2Point struct {
	p bls12381.G2Affine
}

// GT is an element of the target group 𝔾ₜ ⊂ 𝔽p¹², where pairings land.
type GT struct {
	e bls12381.GT
}

// G1Generator returns the standard generator of G1.
func G1Generator() G1Point {
	return G1Point{p: g1Gen}
}

// G2Generator returns the standard generator of G2.
func G2Generator() G2Point {
	return G2Point{p: g2Gen}
}

// G1PointFromCompressed parses a compressed G1 point, checking the
// encoding, that it is on the curve, and that it is in the prime-order
// subgroup.
func G1PointFromCompressed(b []byte) (G1Point, error) {
	var out G1Point
	if len(b) != G1CompressedLen {
		return out, ErrInvalidPoint
	}
	if _, err := out.p.SetBytes(b); err != nil {
		return out, ErrInvalidPoint
	}
	return out, nil
}

// G2PointFromCompressed parses a compressed G2 point, with the same
// checks as G1PointFromCompressed.
func G2PointFromCompressed(b []byte) (G2Point, error) {
	var out G2Point
	if len(b) != G2CompressedLen {
		return out, ErrInvalidPoint
	}
	if _, err := out.p.SetBytes(b); err != nil {
		return out, ErrInvalidPoint
	}
	return out, nil
}

// Bytes returns p compressed.
func (p G1Point) Bytes() [G1CompressedLen]byte {
	return p.p.Bytes()
}

// Bytes returns p compressed.
func (p G2Point) Bytes() [G2CompressedLen]byte {
	return p.p.Bytes()
}

// Equal reports whether p and q are the same point.
func (p G1Point) Equal(q G1Point) bool {
	return p.p.Equal(&q.p)
}

// Equal reports whether p and q are the same point.
func (p G2Point) Equal(q G2Point) bool {
	return p.p.Equal(&q.p)
}

// IsInfinity reports whether p is the point at infinity, the group's
// identity element.
func (p G1Point) IsInfinity() bool {
	return p.p.IsInfinity()
}

// IsInfinity reports whether p is the point at infinity.
func (p G2Point) IsInfinity() bool {
	return p.p.IsInfinity()
}

// Add returns p + q.
func (p G1Point) Add(q G1Point) G1Point {
	var out G1Point
	out.p.Add(&p.p, &q.p)
	return out
}

// Add returns p + q.
func (p G2Point) Add(q G2Point) G2Point {
	var out G2Point
	out.p.Add(&p.p, &q.p)
	return out
}

// Double returns p + p.
func (p G1Point) Double() G1Point {
	var out G1Point
	out.p.Double(&p.p)
	return out
}

// Double returns p + p.
func (p G2Point) Double() G2Point {
	var out G2Point
	out.p.Double(&p.p)
	return out
}

// Neg returns -p.
func (p G1Point) Neg() G1Point {
	var out G1Point
	out.p.Neg(&p.p)
	return out
}

// Neg returns -p.
func (p G2Point) Neg() G2Point {
	var out G2Point
	out.p.Neg(&p.p)
	return out
}

// Mul returns scalar*p, where scalar is a big-endian 32-byte value; it is
// reduced modulo the group order, which changes no result since a point's
// order divides r.
func (p G1Point) Mul(scalar [ScalarLen]byte) G1Point {
	var out G1Point
	out.p.ScalarMultiplication(&p.p, new(big.Int).SetBytes(scalar[:]))
	return out
}

// Mul returns scalar*p, where scalar is a big-endian 32-byte value.
func (p G2Point) Mul(scalar [ScalarLen]byte) G2Point {
	var out G2Point
	out.p.ScalarMultiplication(&p.p, new(big.Int).SetBytes(scalar[:]))
	return out
}

// HashToG1 maps msg to a point in G1 under the domain separation tag dst,
// using RFC 9380's hash-to-curve with the SVDW map and
// expand_message_xmd(SHA-256). This is the "random oracle" variant: the
// output is indifferentiable from a uniformly random point, which is what
// a signature scheme needs.
func HashToG1(msg, dst []byte) (G1Point, error) {
	p, err := bls12381.HashToG1(msg, dst)
	if err != nil {
		return G1Point{}, ErrHashToCurveFailed
	}
	return G1Point{p: p}, nil
}

// HashToG2 is HashToG1's mirror in G2.
func HashToG2(msg, dst []byte) (G2Point, error) {
	p, err := bls12381.HashToG2(msg, dst)
	if err != nil {
		return G2Point{}, ErrHashToCurveFailed
	}
	return G2Point{p: p}, nil
}

// EncodeToG1 maps msg to a point in G1 with a single application of the
// SVDW map, rather than HashToG1's two. It is cheaper but its output is
// *not* indifferentiable from random — use it only where a construction
// explicitly calls for encode_to_curve, never as a drop-in for HashToG1.
func EncodeToG1(msg, dst []byte) (G1Point, error) {
	p, err := bls12381.EncodeToG1(msg, dst)
	if err != nil {
		return G1Point{}, ErrHashToCurveFailed
	}
	return G1Point{p: p}, nil
}

// EncodeToG2 is EncodeToG1's mirror in G2.
func EncodeToG2(msg, dst []byte) (G2Point, error) {
	p, err := bls12381.EncodeToG2(msg, dst)
	if err != nil {
		return G2Point{}, ErrHashToCurveFailed
	}
	return G2Point{p: p}, nil
}

// GTOne returns the multiplicative identity of 𝔽p¹².
func GTOne() GT {
	var out GT
	out.e.SetOne()
	return out
}

// Mul returns a*b.
func (a GT) Mul(b GT) GT {
	var out GT
	out.e.Mul(&a.e, &b.e)
	return out
}

// Sqr returns a².
func (a GT) Sqr() GT {
	var out GT
	out.e.Square(&a.e)
	return out
}

// Inverse returns a⁻¹.
func (a GT) Inverse() GT {
	var out GT
	out.e.Inverse(&a.e)
	return out
}

// IsOne reports whether a is the identity.
func (a GT) IsOne() bool {
	return a.e.IsOne()
}

// Equal reports whether a and b are the same element.
func (a GT) Equal(b GT) bool {
	return a.e.Equal(&b.e)
}

// InGroup reports whether a lies in 𝔾ₜ, the order-r subgroup of 𝔽p¹² —
// not merely in 𝔽p¹². Every pairing output does; an arbitrary 𝔽p¹²
// element read off the wire may not.
func (a GT) InGroup() bool {
	return a.e.IsInSubGroup()
}

// Bytes returns a as 12 big-endian 𝔽p coordinates.
func (a GT) Bytes() [GTLen]byte {
	return a.e.Bytes()
}

// GTFromBytes parses the encoding Bytes produces.
func GTFromBytes(b []byte) (GT, error) {
	var out GT
	if err := out.e.SetBytes(b); err != nil {
		return GT{}, ErrPairingFailed
	}
	return out, nil
}

// MillerLoop computes the Miller loop f(q, p), *without* the final
// exponentiation — so its result is not yet a 𝔾ₜ element. Feed it to
// FinalExp, or accumulate several loops with GT.Mul first and exponentiate
// once, which is the whole point of keeping the two halves separate.
func MillerLoop(q G2Point, p G1Point) (GT, error) {
	f, err := bls12381.MillerLoop([]bls12381.G1Affine{p.p}, []bls12381.G2Affine{q.p})
	if err != nil {
		return GT{}, ErrPairingFailed
	}
	return GT{e: f}, nil
}

// MillerLoopN computes ∏ f(qs[i], ps[i]) in one pass, cheaper than
// multiplying individual MillerLoop results. qs and ps must have the same,
// non-zero length.
func MillerLoopN(qs []G2Point, ps []G1Point) (GT, error) {
	if len(qs) != len(ps) {
		return GT{}, ErrLengthMismatch
	}
	gps, gqs := unwrapPoints(ps, qs)
	f, err := bls12381.MillerLoop(gps, gqs)
	if err != nil {
		return GT{}, ErrPairingFailed
	}
	return GT{e: f}, nil
}

// FinalExp raises f to (p¹²-1)/r, mapping a Miller loop result into 𝔾ₜ.
func FinalExp(f GT) GT {
	return GT{e: bls12381.FinalExponentiation(&f.e)}
}

// Pair is the full reduced pairing e(p, q): a Miller loop followed by the
// final exponentiation.
func Pair(q G2Point, p G1Point) (GT, error) {
	f, err := bls12381.Pair([]bls12381.G1Affine{p.p}, []bls12381.G2Affine{q.p})
	if err != nil {
		return GT{}, ErrPairingFailed
	}
	return GT{e: f}, nil
}

// PairN is ∏ e(ps[i], qs[i]) — one Miller loop over all the terms and a
// single final exponentiation.
func PairN(qs []G2Point, ps []G1Point) (GT, error) {
	if len(qs) != len(ps) {
		return GT{}, ErrLengthMismatch
	}
	gps, gqs := unwrapPoints(ps, qs)
	f, err := bls12381.Pair(gps, gqs)
	if err != nil {
		return GT{}, ErrPairingFailed
	}
	return GT{e: f}, nil
}

// PairingCheck reports whether ∏ e(ps[i], qs[i]) == 1. This is what a
// verification equation reduces to once every term is moved to one side,
// and it is cheaper than PairN followed by IsOne — the check can skip part
// of the final exponentiation.
func PairingCheck(qs []G2Point, ps []G1Point) (bool, error) {
	if len(qs) != len(ps) {
		return false, ErrLengthMismatch
	}
	gps, gqs := unwrapPoints(ps, qs)
	ok, err := bls12381.PairingCheck(gps, gqs)
	if err != nil {
		return false, ErrPairingFailed
	}
	return ok, nil
}

// FinalVerify reports whether a and b pair to the same 𝔾ₜ element, i.e.
// whether FinalExp(a) == FinalExp(b). Use it to compare two Miller loop
// results without exponentiating either one yourself.
func FinalVerify(a, b GT) bool {
	return FinalExp(a).Equal(FinalExp(b))
}

// PrecomputedLines holds the line evaluations for a fixed G2 point. When
// the same q is paired against many different G1 points — a verification
// key against a stream of proofs, say — precomputing its lines once and
// calling MillerLoopLines is materially faster than a fresh MillerLoop per
// point.
type PrecomputedLines struct {
	lines [2][len(bls12381.LoopCounter) - 1]bls12381.LineEvaluationAff
}

// PrecomputeLines computes the line evaluations for q.
func PrecomputeLines(q G2Point) PrecomputedLines {
	return PrecomputedLines{lines: bls12381.PrecomputeLines(q.p)}
}

// MillerLoopLines is MillerLoop against a precomputed q. Like MillerLoop
// it stops short of the final exponentiation.
func MillerLoopLines(lines PrecomputedLines, p G1Point) (GT, error) {
	f, err := bls12381.MillerLoopFixedQ(
		[]bls12381.G1Affine{p.p},
		[][2][len(bls12381.LoopCounter) - 1]bls12381.LineEvaluationAff{lines.lines},
	)
	if err != nil {
		return GT{}, ErrPairingFailed
	}
	return GT{e: f}, nil
}

// unwrapPoints flattens the wrapper types into the backing slices
// gnark-crypto's pairing functions take. Callers have already checked that
// the two have the same length.
func unwrapPoints(ps []G1Point, qs []G2Point) ([]bls12381.G1Affine, []bls12381.G2Affine) {
	gps := make([]bls12381.G1Affine, len(ps))
	gqs := make([]bls12381.G2Affine, len(qs))
	for i := range ps {
		gps[i] = ps[i].p
		gqs[i] = qs[i].p
	}
	return gps, gqs
}
