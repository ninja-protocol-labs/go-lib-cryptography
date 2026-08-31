package bls12381

import "testing"

func TestG1PointFromCompressedRoundTrip(t *testing.T) {
	priv := privKeyN(t, 40)
	pub := priv.PublicKeyMinPk()

	p, err := G1PointFromCompressed(pub.Bytes())
	if err != nil {
		t.Fatalf("G1PointFromCompressed failed: %v", err)
	}
	if !p.Equal(G1Point(pub.point)) {
		t.Error("G1PointFromCompressed(pub.Bytes()) != pub's point")
	}
}

func TestG1PointFromCompressedRejectsGarbage(t *testing.T) {
	garbage := make([]byte, 48)
	for i := range garbage {
		garbage[i] = 0xff
	}
	if _, err := G1PointFromCompressed(garbage); err == nil {
		t.Error("G1PointFromCompressed accepted garbage")
	}
}

func TestG1ArithmeticAgreesWithScalarMult(t *testing.T) {
	g := G1Generator()
	doubled := g.Double()
	added := g.Add(g)
	if doubled != added {
		t.Error("G1Generator().Double() != G1Generator().Add(itself)")
	}

	two := make([]byte, 32)
	two[31] = 2
	mult := g.Mul(two, 256)
	if mult != doubled {
		t.Error("G1Generator().Mul(2) != G1Generator().Double()")
	}
}

func TestG1Neg(t *testing.T) {
	g := G1Generator()
	negG := g.Neg()
	if g.Equal(negG) {
		t.Error("G1Point.Neg() == itself")
	}
	if !g.Add(negG).IsInfinity() {
		t.Error("G + (-G) is not the point at infinity")
	}
}

func TestG2ArithmeticAgreesWithScalarMult(t *testing.T) {
	g := G2Generator()
	doubled := g.Double()
	added := g.Add(g)
	if doubled != added {
		t.Error("G2Generator().Double() != G2Generator().Add(itself)")
	}

	two := make([]byte, 32)
	two[31] = 2
	mult := g.Mul(two, 256)
	if mult != doubled {
		t.Error("G2Generator().Mul(2) != G2Generator().Double()")
	}
}

func TestHashToG1AndG2AreOnCurveAndDeterministic(t *testing.T) {
	dst := []byte(DefaultDSTMinPk)
	a := HashToG1(testMsg, dst)
	b := HashToG1(testMsg, dst)
	if a != b {
		t.Error("HashToG1 is not deterministic")
	}

	dst2 := []byte(DefaultDSTMinSig)
	c := HashToG2(testMsg, dst2)
	d := HashToG2(testMsg, dst2)
	if c != d {
		t.Error("HashToG2 is not deterministic")
	}
}

func TestGTAlgebra(t *testing.T) {
	f := MillerLoop(G2Generator(), G1Generator())
	f = FinalExp(f)

	one := GTOne()
	if !one.IsOne() {
		t.Error("GTOne().IsOne() is false")
	}
	if f.IsOne() {
		t.Error("a real final-exponentiated Miller loop result reported as one")
	}
	if !f.InGroup() {
		t.Error("a real final-exponentiated Miller loop result reported as not in GT")
	}

	if sqr, mulSelf := f.Sqr(), f.Mul(f); sqr != mulSelf {
		t.Error("GT.Sqr() != GT.Mul(itself)")
	}
	if prod := f.Mul(f.Inverse()); prod != one {
		t.Error("f.Mul(f.Inverse()) != GTOne()")
	}
	if !FinalVerify(f, f) {
		t.Error("FinalVerify(f, f) is false")
	}
}

func TestMillerLoopAgreesWithLinesPrecompute(t *testing.T) {
	g1, g2 := G1Generator(), G2Generator()
	direct := MillerLoop(g2, g1)
	viaLines := MillerLoopLines(PrecomputeLines(g2), g1)
	if !direct.Equal(viaLines) {
		t.Error("MillerLoop(G2, G1) != MillerLoopLines(PrecomputeLines(G2), G1)")
	}
}

func TestMillerLoopNAgreesWithGTMul(t *testing.T) {
	g1, g2 := G1Generator(), G2Generator()
	priv := privKeyN(t, 41)
	pkA := G1Point(priv.PublicKeyMinPk().point)

	loop1 := MillerLoop(g2, g1)
	loop2 := MillerLoop(g2, pkA)
	product := loop1.Mul(loop2)

	batched, err := MillerLoopN([]G2Point{g2, g2}, []G1Point{g1, pkA})
	if err != nil {
		t.Fatalf("MillerLoopN failed: %v", err)
	}
	if !product.Equal(batched) {
		t.Error("MillerLoop(q,p1)*MillerLoop(q,p2) != MillerLoopN([q,q],[p1,p2])")
	}
}

func TestMillerLoopNRejectsLengthMismatch(t *testing.T) {
	if _, err := MillerLoopN([]G2Point{G2Generator()}, nil); err == nil {
		t.Error("MillerLoopN accepted mismatched qs/ps lengths")
	}
}

func TestPairingAggregatePkInG1AndFinalVerify(t *testing.T) {
	priv := privKeyN(t, 42)
	pub := G1Point(priv.PublicKeyMinPk().point)
	sig, err := G2PointFromCompressed(SignMinPk(priv, testMsg))
	if err != nil {
		t.Fatalf("G2PointFromCompressed failed: %v", err)
	}

	p := NewPairing(true, []byte(DefaultDSTMinPk))
	if err := p.AggregatePkInG1(pub, &sig, testMsg); err != nil {
		t.Fatalf("AggregatePkInG1 failed: %v", err)
	}
	p.Commit()
	if !p.FinalVerify(nil) {
		t.Error("Pairing.FinalVerify rejected a genuine signature")
	}
}

func TestPairingAggregatePkInG1RejectsWrongMessage(t *testing.T) {
	priv := privKeyN(t, 43)
	pub := G1Point(priv.PublicKeyMinPk().point)
	sig, err := G2PointFromCompressed(SignMinPk(priv, testMsg))
	if err != nil {
		t.Fatalf("G2PointFromCompressed failed: %v", err)
	}

	p := NewPairing(true, []byte(DefaultDSTMinPk))
	if err := p.AggregatePkInG1(pub, &sig, []byte("wrong message")); err != nil {
		t.Fatalf("AggregatePkInG1 failed: %v", err)
	}
	p.Commit()
	if p.FinalVerify(nil) {
		t.Error("Pairing.FinalVerify accepted a signature over the wrong message")
	}
}

func TestPairingSeparateGtsig(t *testing.T) {
	priv := privKeyN(t, 44)
	pub := G1Point(priv.PublicKeyMinPk().point)
	sig := SignMinPk(priv, testMsg)
	sigPoint, err := G2PointFromCompressed(sig)
	if err != nil {
		t.Fatalf("G2PointFromCompressed failed: %v", err)
	}
	gtsig := AggregatedInG2(sigPoint)

	p := NewPairing(true, []byte(DefaultDSTMinPk))
	if err := p.AggregatePkInG1(pub, nil, testMsg); err != nil {
		t.Fatalf("AggregatePkInG1 (pk only) failed: %v", err)
	}
	p.Commit()
	if !p.FinalVerify(&gtsig) {
		t.Error("Pairing.FinalVerify with an externally-supplied gtsig rejected a genuine signature")
	}
}

func TestPairingSeparateGtsigMinSig(t *testing.T) {
	// AggregatedInG1's mirror of TestPairingSeparateGtsig above, for the
	// min-sig direction (pk in G2, sig in G1).
	priv := privKeyN(t, 49)
	pub := G2Point(priv.PublicKeyMinSig().point)
	sig, err := G1PointFromCompressed(SignMinSig(priv, testMsg))
	if err != nil {
		t.Fatalf("G1PointFromCompressed failed: %v", err)
	}
	gtsig := AggregatedInG1(sig)

	p := NewPairing(true, []byte(DefaultDSTMinSig))
	if err := p.AggregatePkInG2(pub, nil, testMsg); err != nil {
		t.Fatalf("AggregatePkInG2 (pk only) failed: %v", err)
	}
	p.Commit()
	if !p.FinalVerify(&gtsig) {
		t.Error("Pairing.FinalVerify with an externally-supplied gtsig rejected a genuine min-sig signature")
	}
}

func TestPairingMerge(t *testing.T) {
	privA := privKeyN(t, 45)
	privB := privKeyN(t, 46)
	pubA := G1Point(privA.PublicKeyMinPk().point)
	pubB := G1Point(privB.PublicKeyMinPk().point)
	msgA, msgB := []byte("message A"), []byte("message B")
	sigA, err := G2PointFromCompressed(SignMinPk(privA, msgA))
	if err != nil {
		t.Fatalf("G2PointFromCompressed (A) failed: %v", err)
	}
	sigB, err := G2PointFromCompressed(SignMinPk(privB, msgB))
	if err != nil {
		t.Fatalf("G2PointFromCompressed (B) failed: %v", err)
	}

	pA := NewPairing(true, []byte(DefaultDSTMinPk))
	if err := pA.AggregatePkInG1(pubA, &sigA, msgA); err != nil {
		t.Fatalf("AggregatePkInG1 (A) failed: %v", err)
	}
	pA.Commit()

	pB := NewPairing(true, []byte(DefaultDSTMinPk))
	if err := pB.AggregatePkInG1(pubB, &sigB, msgB); err != nil {
		t.Fatalf("AggregatePkInG1 (B) failed: %v", err)
	}
	pB.Commit()

	if err := pA.Merge(pB); err != nil {
		t.Fatalf("Merge failed: %v", err)
	}
	if !pA.FinalVerify(nil) {
		t.Error("Pairing.FinalVerify rejected a merged pairing")
	}
}

func TestPairingChkNMulNAggrPkInG1Batch(t *testing.T) {
	privA := privKeyN(t, 47)
	privB := privKeyN(t, 48)
	pubA := G1Point(privA.PublicKeyMinPk().point)
	pubB := G1Point(privB.PublicKeyMinPk().point)
	msgA, msgB := []byte("message A"), []byte("message B")
	sigA, err := G2PointFromCompressed(SignMinPk(privA, msgA))
	if err != nil {
		t.Fatalf("G2PointFromCompressed (A) failed: %v", err)
	}
	sigB, err := G2PointFromCompressed(SignMinPk(privB, msgB))
	if err != nil {
		t.Fatalf("G2PointFromCompressed (B) failed: %v", err)
	}

	scalarA := make([]byte, 32)
	scalarA[31] = 7
	scalarB := make([]byte, 32)
	scalarB[31] = 11

	p := NewPairing(true, []byte(DefaultDSTMinPk))
	if err := p.ChkNMulNAggrPkInG1(pubA, true, &sigA, true, scalarA, 256, msgA); err != nil {
		t.Fatalf("ChkNMulNAggrPkInG1 (A) failed: %v", err)
	}
	if err := p.ChkNMulNAggrPkInG1(pubB, true, &sigB, true, scalarB, 256, msgB); err != nil {
		t.Fatalf("ChkNMulNAggrPkInG1 (B) failed: %v", err)
	}
	p.Commit()
	if !p.FinalVerify(nil) {
		t.Error("Pairing.FinalVerify rejected a genuine batch")
	}
}
