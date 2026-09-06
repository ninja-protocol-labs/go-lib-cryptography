package bn254

import (
	"bytes"
	"testing"
)

func TestG1PointFromCompressedRoundTrip(t *testing.T) {
	pub := g1PointN(t, 40)
	b := pub.Bytes()
	p, err := G1PointFromCompressed(b[:])
	if err != nil {
		t.Fatalf("G1PointFromCompressed failed: %v", err)
	}
	if p.Bytes() != pub.Bytes() {
		t.Error("G1PointFromCompressed(pub.Bytes()).Bytes() != pub.Bytes()")
	}
}

func TestG2PointFromCompressedRoundTrip(t *testing.T) {
	pub := g2PointN(t, 40)
	b := pub.Bytes()
	p, err := G2PointFromCompressed(b[:])
	if err != nil {
		t.Fatalf("G2PointFromCompressed failed: %v", err)
	}
	if p.Bytes() != pub.Bytes() {
		t.Error("G2PointFromCompressed(pub.Bytes()).Bytes() != pub.Bytes()")
	}
}

func TestPointFromCompressedRejectsGarbage(t *testing.T) {
	if _, err := G1PointFromCompressed(bytes.Repeat([]byte{0xff}, G1CompressedLen)); err == nil {
		t.Error("G1PointFromCompressed accepted garbage")
	}
	if _, err := G2PointFromCompressed(bytes.Repeat([]byte{0xff}, G2CompressedLen)); err == nil {
		t.Error("G2PointFromCompressed accepted garbage")
	}
	if _, err := G1PointFromCompressed(nil); err == nil {
		t.Error("G1PointFromCompressed accepted an empty input")
	}
}

func TestG1ArithmeticAgreesWithScalarMult(t *testing.T) {
	g := G1Generator()
	doubled := g.Double()
	if added := g.Add(g); doubled != added {
		t.Error("G1Generator().Double() != G1Generator().Add(itself)")
	}
	if mult := g.Mul(scalarArrN(t, 2)); mult != doubled {
		t.Error("G1Generator().Mul(2) != G1Generator().Double()")
	}
	// 3G = 2G + G, reached two ways.
	if g.Mul(scalarArrN(t, 3)) != doubled.Add(g) {
		t.Error("G1Generator().Mul(3) != 2G + G")
	}
}

func TestG2ArithmeticAgreesWithScalarMult(t *testing.T) {
	g := G2Generator()
	doubled := g.Double()
	if added := g.Add(g); doubled != added {
		t.Error("G2Generator().Double() != G2Generator().Add(itself)")
	}
	if mult := g.Mul(scalarArrN(t, 2)); mult != doubled {
		t.Error("G2Generator().Mul(2) != G2Generator().Double()")
	}
}

func TestNeg(t *testing.T) {
	g1 := G1Generator()
	if g1.Equal(g1.Neg()) {
		t.Error("G1Point.Neg() == itself")
	}
	if !g1.Add(g1.Neg()).IsInfinity() {
		t.Error("G + (-G) is not the point at infinity in G1")
	}

	g2 := G2Generator()
	if !g2.Add(g2.Neg()).IsInfinity() {
		t.Error("G + (-G) is not the point at infinity in G2")
	}
}

func TestHashToCurveIsDeterministicAndDomainSeparated(t *testing.T) {
	dst := testDST

	a, err := HashToG1(testMsg, dst)
	if err != nil {
		t.Fatalf("HashToG1 failed: %v", err)
	}
	b, err := HashToG1(testMsg, dst)
	if err != nil {
		t.Fatalf("HashToG1 failed: %v", err)
	}
	if a != b {
		t.Error("HashToG1 is not deterministic")
	}

	other, err := HashToG1(testMsg, []byte("A_DIFFERENT_DST_"))
	if err != nil {
		t.Fatalf("HashToG1 failed: %v", err)
	}
	if a == other {
		t.Error("HashToG1 ignored the domain separation tag")
	}

	c, err := HashToG2(testMsg, testDST)
	if err != nil {
		t.Fatalf("HashToG2 failed: %v", err)
	}
	d, err := HashToG2(testMsg, testDST)
	if err != nil {
		t.Fatalf("HashToG2 failed: %v", err)
	}
	if c != d {
		t.Error("HashToG2 is not deterministic")
	}
}

func TestEncodeToCurveDiffersFromHashToCurve(t *testing.T) {
	dst := testDST
	h, err := HashToG1(testMsg, dst)
	if err != nil {
		t.Fatalf("HashToG1 failed: %v", err)
	}
	e, err := EncodeToG1(testMsg, dst)
	if err != nil {
		t.Fatalf("EncodeToG1 failed: %v", err)
	}
	if h == e {
		t.Error("EncodeToG1 and HashToG1 produced the same point")
	}
	if _, err := EncodeToG2(testMsg, dst); err != nil {
		t.Fatalf("EncodeToG2 failed: %v", err)
	}
}

func TestHashToCurveRejectsOverlongDST(t *testing.T) {
	dst := bytes.Repeat([]byte{'x'}, 256)
	if _, err := HashToG1(testMsg, dst); err == nil {
		t.Error("HashToG1 accepted a 256-byte DST")
	}
	if _, err := HashToG2(testMsg, dst); err == nil {
		t.Error("HashToG2 accepted a 256-byte DST")
	}
	if _, err := EncodeToG1(testMsg, dst); err == nil {
		t.Error("EncodeToG1 accepted a 256-byte DST")
	}
	if _, err := EncodeToG2(testMsg, dst); err == nil {
		t.Error("EncodeToG2 accepted a 256-byte DST")
	}
}

func TestGTAlgebra(t *testing.T) {
	f, err := Pair(G2Generator(), G1Generator())
	if err != nil {
		t.Fatalf("Pair failed: %v", err)
	}

	one := GTOne()
	if !one.IsOne() {
		t.Error("GTOne().IsOne() is false")
	}
	if f.IsOne() {
		t.Error("e(G1, G2) reported as one")
	}
	if !f.InGroup() {
		t.Error("e(G1, G2) reported as not in GT")
	}
	if f.Sqr() != f.Mul(f) {
		t.Error("GT.Sqr() != GT.Mul(itself)")
	}
	if f.Mul(f.Inverse()) != one {
		t.Error("f.Mul(f.Inverse()) != GTOne()")
	}
}

func TestGTBytesRoundTrip(t *testing.T) {
	f, err := Pair(G2Generator(), G1Generator())
	if err != nil {
		t.Fatalf("Pair failed: %v", err)
	}
	b := f.Bytes()
	same, err := GTFromBytes(b[:])
	if err != nil {
		t.Fatalf("GTFromBytes failed: %v", err)
	}
	if !f.Equal(same) {
		t.Error("GTFromBytes(f.Bytes()) != f")
	}
	if _, err := GTFromBytes(nil); err == nil {
		t.Error("GTFromBytes accepted an empty input")
	}
}

func TestPairIsMillerLoopThenFinalExp(t *testing.T) {
	g1, g2 := G1Generator(), G2Generator()
	direct, err := Pair(g2, g1)
	if err != nil {
		t.Fatalf("Pair failed: %v", err)
	}
	loop, err := MillerLoop(g2, g1)
	if err != nil {
		t.Fatalf("MillerLoop failed: %v", err)
	}
	if !direct.Equal(FinalExp(loop)) {
		t.Error("Pair != FinalExp(MillerLoop)")
	}
}

func TestPairingBilinearity(t *testing.T) {
	// e(a*G1, b*G2) == e(G1, G2)^(a*b), checked as e(3G1, 5G2) ==
	// e(15G1, G2) == e(G1, 15G2).
	g1, g2 := G1Generator(), G2Generator()

	lhs, err := Pair(g2.Mul(scalarArrN(t, 5)), g1.Mul(scalarArrN(t, 3)))
	if err != nil {
		t.Fatalf("Pair failed: %v", err)
	}
	viaG1, err := Pair(g2, g1.Mul(scalarArrN(t, 15)))
	if err != nil {
		t.Fatalf("Pair failed: %v", err)
	}
	viaG2, err := Pair(g2.Mul(scalarArrN(t, 15)), g1)
	if err != nil {
		t.Fatalf("Pair failed: %v", err)
	}

	if !lhs.Equal(viaG1) {
		t.Error("e(3G1, 5G2) != e(15G1, G2)")
	}
	if !lhs.Equal(viaG2) {
		t.Error("e(3G1, 5G2) != e(G1, 15G2)")
	}
}

func TestMillerLoopAgreesWithLinesPrecompute(t *testing.T) {
	g1, g2 := G1Generator(), G2Generator()
	direct, err := MillerLoop(g2, g1)
	if err != nil {
		t.Fatalf("MillerLoop failed: %v", err)
	}
	viaLines, err := MillerLoopLines(PrecomputeLines(g2), g1)
	if err != nil {
		t.Fatalf("MillerLoopLines failed: %v", err)
	}
	// The two loops accumulate the same pairing but not necessarily the
	// same 𝔽p¹² representative, so they are compared after the final
	// exponentiation — which is what FinalVerify does.
	if !FinalVerify(direct, viaLines) {
		t.Error("MillerLoop and MillerLoopLines disagree after FinalExp")
	}
}

func TestMillerLoopNAgreesWithGTMul(t *testing.T) {
	g1, g2 := G1Generator(), G2Generator()
	pkBytes := g1PointN(t, 41).Bytes()
	pkA, err := G1PointFromCompressed(pkBytes[:])
	if err != nil {
		t.Fatalf("G1PointFromCompressed failed: %v", err)
	}

	loop1, err := MillerLoop(g2, g1)
	if err != nil {
		t.Fatalf("MillerLoop failed: %v", err)
	}
	loop2, err := MillerLoop(g2, pkA)
	if err != nil {
		t.Fatalf("MillerLoop failed: %v", err)
	}

	batched, err := MillerLoopN([]G2Point{g2, g2}, []G1Point{g1, pkA})
	if err != nil {
		t.Fatalf("MillerLoopN failed: %v", err)
	}
	if !loop1.Mul(loop2).Equal(batched) {
		t.Error("MillerLoop(q,p1)*MillerLoop(q,p2) != MillerLoopN([q,q],[p1,p2])")
	}
}

func TestPairNAgreesWithGTMul(t *testing.T) {
	g1, g2 := G1Generator(), G2Generator()
	single, err := Pair(g2, g1)
	if err != nil {
		t.Fatalf("Pair failed: %v", err)
	}
	batched, err := PairN([]G2Point{g2, g2}, []G1Point{g1, g1})
	if err != nil {
		t.Fatalf("PairN failed: %v", err)
	}
	if !single.Sqr().Equal(batched) {
		t.Error("PairN([q,q],[p,p]) != Pair(q,p)²")
	}
}

func TestPairingCheck(t *testing.T) {
	// e(G1, G2) * e(-G1, G2) == 1.
	g1, g2 := G1Generator(), G2Generator()
	ok, err := PairingCheck([]G2Point{g2, g2}, []G1Point{g1, g1.Neg()})
	if err != nil {
		t.Fatalf("PairingCheck failed: %v", err)
	}
	if !ok {
		t.Error("PairingCheck rejected e(G1,G2)*e(-G1,G2) == 1")
	}

	ok, err = PairingCheck([]G2Point{g2}, []G1Point{g1})
	if err != nil {
		t.Fatalf("PairingCheck failed: %v", err)
	}
	if ok {
		t.Error("PairingCheck accepted e(G1,G2) == 1")
	}
}

func TestPairingFunctionsRejectLengthMismatch(t *testing.T) {
	g1, g2 := G1Generator(), G2Generator()
	if _, err := MillerLoopN([]G2Point{g2}, nil); err == nil {
		t.Error("MillerLoopN accepted mismatched lengths")
	}
	if _, err := PairN([]G2Point{g2}, nil); err == nil {
		t.Error("PairN accepted mismatched lengths")
	}
	if _, err := PairingCheck(nil, []G1Point{g1}); err == nil {
		t.Error("PairingCheck accepted mismatched lengths")
	}
}

func TestFinalVerify(t *testing.T) {
	g1, g2 := G1Generator(), G2Generator()
	f, err := MillerLoop(g2, g1)
	if err != nil {
		t.Fatalf("MillerLoop failed: %v", err)
	}
	other, err := MillerLoop(g2, g1.Double())
	if err != nil {
		t.Fatalf("MillerLoop failed: %v", err)
	}
	if !FinalVerify(f, f) {
		t.Error("FinalVerify(f, f) is false")
	}
	if FinalVerify(f, other) {
		t.Error("FinalVerify accepted two different pairings")
	}
}

func TestBLSVerificationEquation(t *testing.T) {
	// The equation a BLS signature satisfies, written with this package's
	// primitives alone: with pk = x*G1 and sig = x*H(m),
	// e(pk, H(m)) * e(-G1, sig) == 1.
	x := scalarArrN(t, 42)
	pk := G1Generator().Mul(x)

	h, err := HashToG2(testMsg, testDST)
	if err != nil {
		t.Fatalf("HashToG2 failed: %v", err)
	}
	sig := h.Mul(x)

	ok, err := PairingCheck([]G2Point{h, sig}, []G1Point{pk, G1Generator().Neg()})
	if err != nil {
		t.Fatalf("PairingCheck failed: %v", err)
	}
	if !ok {
		t.Error("the BLS verification equation did not hold")
	}
}
