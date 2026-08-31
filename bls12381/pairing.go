package bls12381

import "github.com/ninja-protocol-labs/go-lib-cryptography/bls12381/internal"

// Pairing-based primitives for protocols that build their own pairing
// equations rather than using Sign*/Verify*/AggregateVerify* above. G1Point
// and G2Point are raw, already-parsed curve points (the affine wire form,
// not compressed); GT is a raw Fp12 element, the pairing's target group.
//
// Methods take value receivers (not pointers) so results chain naturally
// (e.g. G1Generator().Double().Add(p)) — a value receiver's parameter is
// always addressable inside the method body, so &p below never needs an
// intermediate copy to become one.

// G1Point is a point on G1, in affine form.
type G1Point [internal.P1AffineLen]byte

// G2Point is a point on G2, in affine form.
type G2Point [internal.P2AffineLen]byte

// GT is an element of the pairing's target group (Fp12).
type GT [internal.Fp12Len]byte

// G1Generator returns G1's generator point.
func G1Generator() G1Point {
	return internal.P1AffineGenerator()
}

// G2Generator returns G2's generator point.
func G2Generator() G2Point {
	return internal.P2AffineGenerator()
}

// G1PointFromCompressed parses a 48-byte compressed G1 point, checking both
// its curve and subgroup membership.
func G1PointFromCompressed(b []byte) (G1Point, error) {
	var zero G1Point
	if len(b) != internal.P1CompressedLen {
		return zero, ErrInvalidPublicKey
	}
	var compressed [internal.P1CompressedLen]byte
	copy(compressed[:], b)
	point, code := internal.P1Uncompress(&compressed)
	if code != internal.ErrSuccess {
		return zero, ErrInvalidPublicKey
	}
	if !internal.P1AffineInG1(&point) {
		return zero, ErrInvalidPublicKey
	}
	return point, nil
}

// G2PointFromCompressed is G1PointFromCompressed's mirror in G2.
func G2PointFromCompressed(b []byte) (G2Point, error) {
	var zero G2Point
	if len(b) != internal.P2CompressedLen {
		return zero, ErrInvalidPublicKey
	}
	var compressed [internal.P2CompressedLen]byte
	copy(compressed[:], b)
	point, code := internal.P2Uncompress(&compressed)
	if code != internal.ErrSuccess {
		return zero, ErrInvalidPublicKey
	}
	if !internal.P2AffineInG2(&point) {
		return zero, ErrInvalidPublicKey
	}
	return point, nil
}

// Bytes returns p's 48-byte compressed encoding.
func (p G1Point) Bytes() []byte {
	compressed := internal.P1AffineCompress((*[internal.P1AffineLen]byte)(&p))
	out := make([]byte, internal.P1CompressedLen)
	copy(out, compressed[:])
	return out
}

// Bytes returns p's 96-byte compressed encoding.
func (p G2Point) Bytes() []byte {
	compressed := internal.P2AffineCompress((*[internal.P2AffineLen]byte)(&p))
	out := make([]byte, internal.P2CompressedLen)
	copy(out, compressed[:])
	return out
}

func (p G1Point) Equal(q G1Point) bool {
	return internal.P1AffineIsEqual((*[internal.P1AffineLen]byte)(&p), (*[internal.P1AffineLen]byte)(&q))
}

func (p G2Point) Equal(q G2Point) bool {
	return internal.P2AffineIsEqual((*[internal.P2AffineLen]byte)(&p), (*[internal.P2AffineLen]byte)(&q))
}

func (p G1Point) IsInfinity() bool {
	return internal.P1AffineIsInf((*[internal.P1AffineLen]byte)(&p))
}

func (p G2Point) IsInfinity() bool {
	return internal.P2AffineIsInf((*[internal.P2AffineLen]byte)(&p))
}

func (p G1Point) Add(q G1Point) G1Point {
	return internal.P1Add((*[internal.P1AffineLen]byte)(&p), (*[internal.P1AffineLen]byte)(&q))
}

func (p G2Point) Add(q G2Point) G2Point {
	return internal.P2Add((*[internal.P2AffineLen]byte)(&p), (*[internal.P2AffineLen]byte)(&q))
}

func (p G1Point) Double() G1Point {
	return internal.P1Double((*[internal.P1AffineLen]byte)(&p))
}

func (p G2Point) Double() G2Point {
	return internal.P2Double((*[internal.P2AffineLen]byte)(&p))
}

func (p G1Point) Neg() G1Point {
	return internal.P1Neg((*[internal.P1AffineLen]byte)(&p))
}

func (p G2Point) Neg() G2Point {
	return internal.P2Neg((*[internal.P2AffineLen]byte)(&p))
}

// Mul multiplies p by a big-endian scalar of up to 32 bytes. nbits is the
// scalar's width in bits, not bytes.
func (p G1Point) Mul(scalar []byte, nbits int) G1Point {
	return internal.P1Mult((*[internal.P1AffineLen]byte)(&p), scalar, nbits)
}

// Mul is Mul's mirror in G2.
func (p G2Point) Mul(scalar []byte, nbits int) G2Point {
	return internal.P2Mult((*[internal.P2AffineLen]byte)(&p), scalar, nbits)
}

// HashToG1 implements RFC 9380 hash-to-curve into G1. dst is the domain
// separation tag.
func HashToG1(msg, dst []byte) G1Point {
	return internal.HashToG1(msg, dst, nil)
}

// HashToG2 is HashToG1's mirror into G2.
func HashToG2(msg, dst []byte) G2Point {
	return internal.HashToG2(msg, dst, nil)
}

// Mul multiplies a by b.
func (a GT) Mul(b GT) GT {
	return internal.Fp12Mul((*[internal.Fp12Len]byte)(&a), (*[internal.Fp12Len]byte)(&b))
}

func (a GT) Sqr() GT {
	return internal.Fp12Sqr((*[internal.Fp12Len]byte)(&a))
}

func (a GT) Inverse() GT {
	return internal.Fp12Inverse((*[internal.Fp12Len]byte)(&a))
}

// GTOne returns the target group's identity element.
func GTOne() GT {
	return internal.Fp12One()
}

func (a GT) IsOne() bool {
	return internal.Fp12IsOne((*[internal.Fp12Len]byte)(&a))
}

func (a GT) Equal(b GT) bool {
	return internal.Fp12IsEqual((*[internal.Fp12Len]byte)(&a), (*[internal.Fp12Len]byte)(&b))
}

// InGroup reports whether a is in GT, the pairing's target subgroup —
// meaningful for an Fp12 element that did not come from FinalExp/a Miller
// loop's own output (which are always in GT by construction).
func (a GT) InGroup() bool {
	return internal.Fp12InGroup((*[internal.Fp12Len]byte)(&a))
}

// MillerLoop computes the Miller loop of (q, p) — the pairing's first
// stage, without the final exponentiation.
func MillerLoop(q G2Point, p G1Point) GT {
	return internal.MillerLoop((*[internal.P2AffineLen]byte)(&q), (*[internal.P1AffineLen]byte)(&p))
}

// MillerLoopN computes the product of len(qs) Miller loops; qs and ps must
// have the same length.
func MillerLoopN(qs []G2Point, ps []G1Point) (GT, error) {
	var zero GT
	if len(qs) != len(ps) {
		return zero, ErrLengthMismatch
	}
	qbuf := make([]byte, 0, len(qs)*internal.P2AffineLen)
	pbuf := make([]byte, 0, len(ps)*internal.P1AffineLen)
	for i := range qs {
		qbuf = append(qbuf, qs[i][:]...)
		pbuf = append(pbuf, ps[i][:]...)
	}
	return internal.MillerLoopN(qbuf, pbuf), nil
}

// FinalExp applies the pairing's final exponentiation to a raw Miller loop
// result.
func FinalExp(f GT) GT {
	return internal.FinalExp((*[internal.Fp12Len]byte)(&f))
}

// PrecomputedLines caches the G2-dependent half of a Miller loop for a
// fixed q, so it can be paired against many p (via MillerLoopLines) without
// redoing that work each time.
type PrecomputedLines [internal.LinesLen]byte

// PrecomputeLines computes q's PrecomputedLines.
func PrecomputeLines(q G2Point) PrecomputedLines {
	return internal.PrecomputeLines((*[internal.P2AffineLen]byte)(&q))
}

// MillerLoopLines computes the Miller loop of p against lines.
func MillerLoopLines(lines PrecomputedLines, p G1Point) GT {
	return internal.MillerLoopLines((*[internal.LinesLen]byte)(&lines), (*[internal.P1AffineLen]byte)(&p))
}

// FinalVerify compares a and b's final exponentiations without
// materializing either one — the primitive Pairing.FinalVerify is built
// on.
func FinalVerify(a, b GT) bool {
	return internal.Fp12FinalVerify((*[internal.Fp12Len]byte)(&a), (*[internal.Fp12Len]byte)(&b))
}

// AggregatedInG1 turns an aggregated G1 signature into the GT element
// Pairing.FinalVerify expects as its gtsig argument.
func AggregatedInG1(sig G1Point) GT {
	return internal.AggregatedInG1((*[internal.P1AffineLen]byte)(&sig))
}

// AggregatedInG2 is AggregatedInG1's mirror for a G2 signature.
func AggregatedInG2(sig G2Point) GT {
	return internal.AggregatedInG2((*[internal.P2AffineLen]byte)(&sig))
}

// Pairing is a multi-pairing accumulation session: aggregate any number of
// (public key, signature, message) triples across one or more calls, then
// check the accumulated product in one FinalVerify. This is what
// AggregateVerifyMinPk/MinSig are built on; use it directly for a custom
// pairing equation (e.g. verifying against a gtsig computed separately via
// AggregatedInG1/AggregatedInG2).
type Pairing struct {
	ctx []byte
}

// NewPairing starts a session. hashOrEncode selects hash-to-curve (true) or
// encode-to-curve (false) for every aggregate call made against it; dst is
// the domain separation tag used throughout the session.
func NewPairing(hashOrEncode bool, dst []byte) *Pairing {
	ctx := make([]byte, internal.PairingSizeof()+len(dst))
	internal.PairingInit(ctx, hashOrEncode, dst)
	return &Pairing{ctx: ctx}
}

// AggregatePkInG1 aggregates one pk/sig/message triple, for the min-pk
// scheme (pk in G1, sig in G2). sig is an already-parsed point (e.g. from
// G2PointFromCompressed) — the internal pairing engine works in affine
// point form, not the compressed wire encoding Sign* return, so a raw
// compressed []byte cannot be passed through directly. sig may be nil to
// aggregate only the pk side, when the caller supplies a gtsig to
// FinalVerify separately.
func (p *Pairing) AggregatePkInG1(pk G1Point, sig *G2Point, msg []byte) error {
	var sigBytes []byte
	if sig != nil {
		sigBytes = sig[:]
	}
	if internal.PairingAggregatePkInG1(p.ctx, (*[internal.P1AffineLen]byte)(&pk), sigBytes, msg, nil) != internal.ErrSuccess {
		return ErrPairingFailed
	}
	return nil
}

// AggregatePkInG2 is AggregatePkInG1's mirror for the min-sig scheme.
func (p *Pairing) AggregatePkInG2(pk G2Point, sig *G1Point, msg []byte) error {
	var sigBytes []byte
	if sig != nil {
		sigBytes = sig[:]
	}
	if internal.PairingAggregatePkInG2(p.ctx, (*[internal.P2AffineLen]byte)(&pk), sigBytes, msg, nil) != internal.ErrSuccess {
		return ErrPairingFailed
	}
	return nil
}

// ChkNAggrPkInG1 is AggregatePkInG1 plus the subgroup checks blst
// otherwise leaves to the caller — what anything arriving off the wire
// wants. Since every G1Point/G2Point this package constructs is already
// subgroup-checked (G1PointFromCompressed/G2PointFromCompressed validate
// at parse time, and arithmetic on valid points stays valid), pkGrpchk/
// sigGrpchk exist mainly for parity with the internal/blst API — pass
// false for either side already known valid to skip redoing that check.
func (p *Pairing) ChkNAggrPkInG1(pk G1Point, pkGrpchk bool, sig *G2Point, sigGrpchk bool, msg []byte) error {
	var sigBytes []byte
	if sig != nil {
		sigBytes = sig[:]
	}
	if internal.PairingChkNAggrPkInG1(p.ctx, (*[internal.P1AffineLen]byte)(&pk), pkGrpchk, sigBytes, sigGrpchk, msg, nil) != internal.ErrSuccess {
		return ErrPairingFailed
	}
	return nil
}

// ChkNAggrPkInG2 is ChkNAggrPkInG1's mirror for the min-sig scheme.
func (p *Pairing) ChkNAggrPkInG2(pk G2Point, pkGrpchk bool, sig *G1Point, sigGrpchk bool, msg []byte) error {
	var sigBytes []byte
	if sig != nil {
		sigBytes = sig[:]
	}
	if internal.PairingChkNAggrPkInG2(p.ctx, (*[internal.P2AffineLen]byte)(&pk), pkGrpchk, sigBytes, sigGrpchk, msg, nil) != internal.ErrSuccess {
		return ErrPairingFailed
	}
	return nil
}

// MulNAggregatePkInG1 is AggregatePkInG1 with a per-entry random scalar
// folded in, which is what makes batch verification sound against an
// adversary who picked the signatures. scalar is big-endian, up to 32
// bytes; nbits is its width in bits.
func (p *Pairing) MulNAggregatePkInG1(pk G1Point, sig *G2Point, scalar []byte, nbits int, msg []byte) error {
	var sigBytes []byte
	if sig != nil {
		sigBytes = sig[:]
	}
	if internal.PairingMulNAggregatePkInG1(p.ctx, (*[internal.P1AffineLen]byte)(&pk), sigBytes, scalar, nbits, msg, nil) != internal.ErrSuccess {
		return ErrPairingFailed
	}
	return nil
}

// MulNAggregatePkInG2 is MulNAggregatePkInG1's mirror for the min-sig
// scheme.
func (p *Pairing) MulNAggregatePkInG2(pk G2Point, sig *G1Point, scalar []byte, nbits int, msg []byte) error {
	var sigBytes []byte
	if sig != nil {
		sigBytes = sig[:]
	}
	if internal.PairingMulNAggregatePkInG2(p.ctx, (*[internal.P2AffineLen]byte)(&pk), sigBytes, scalar, nbits, msg, nil) != internal.ErrSuccess {
		return ErrPairingFailed
	}
	return nil
}

// ChkNMulNAggrPkInG1 combines ChkNAggrPkInG1's subgroup checks with
// MulNAggregatePkInG1's random-scalar batching — the form to use for
// batch-verifying signatures straight off the wire.
func (p *Pairing) ChkNMulNAggrPkInG1(pk G1Point, pkGrpchk bool, sig *G2Point, sigGrpchk bool, scalar []byte, nbits int, msg []byte) error {
	var sigBytes []byte
	if sig != nil {
		sigBytes = sig[:]
	}
	if internal.PairingChkNMulNAggrPkInG1(p.ctx, (*[internal.P1AffineLen]byte)(&pk), pkGrpchk, sigBytes, sigGrpchk, scalar, nbits, msg, nil) != internal.ErrSuccess {
		return ErrPairingFailed
	}
	return nil
}

// ChkNMulNAggrPkInG2 is ChkNMulNAggrPkInG1's mirror for the min-sig scheme.
func (p *Pairing) ChkNMulNAggrPkInG2(pk G2Point, pkGrpchk bool, sig *G1Point, sigGrpchk bool, scalar []byte, nbits int, msg []byte) error {
	var sigBytes []byte
	if sig != nil {
		sigBytes = sig[:]
	}
	if internal.PairingChkNMulNAggrPkInG2(p.ctx, (*[internal.P2AffineLen]byte)(&pk), pkGrpchk, sigBytes, sigGrpchk, scalar, nbits, msg, nil) != internal.ErrSuccess {
		return ErrPairingFailed
	}
	return nil
}

// Commit finalizes p's accumulated Miller loop products, required before
// FinalVerify or Merge.
func (p *Pairing) Commit() {
	internal.PairingCommit(p.ctx)
}

// Merge folds other (already Commit-ed) into p.
func (p *Pairing) Merge(other *Pairing) error {
	if internal.PairingMerge(p.ctx, other.ctx) != internal.ErrSuccess {
		return ErrPairingFailed
	}
	return nil
}

// FinalVerify checks p's accumulated pairing. gtsig is the GT-element form
// of a signature aggregated separately (see AggregatedInG1/AggregatedInG2);
// pass nil when every signature was folded into p by the aggregate calls
// instead.
func (p *Pairing) FinalVerify(gtsig *GT) bool {
	return internal.PairingFinalVerify(p.ctx, (*[internal.Fp12Len]byte)(gtsig))
}
