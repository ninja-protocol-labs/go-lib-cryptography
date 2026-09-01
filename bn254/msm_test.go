package bn254

import "testing"

func TestMultiScalarMultG1AgreesWithIndividualMuls(t *testing.T) {
	g := G1Generator()
	pkBytes := privKeyN(t, 50).PublicKeyMinPk().Bytes()
	pkA, err := G1PointFromCompressed(pkBytes[:])
	if err != nil {
		t.Fatalf("G1PointFromCompressed failed: %v", err)
	}

	s1, s2 := scalarN(7), scalarN(11)
	want := g.Mul(s1).Add(pkA.Mul(s2))

	got, err := MultiScalarMultG1([]G1Point{g, pkA}, [][SeckeyLen]byte{s1, s2})
	if err != nil {
		t.Fatalf("MultiScalarMultG1 failed: %v", err)
	}
	if got != want {
		t.Error("MultiScalarMultG1 disagrees with individual Mul+Add")
	}
}

func TestMultiScalarMultG2AgreesWithIndividualMuls(t *testing.T) {
	g := G2Generator()
	pkBytes := privKeyN(t, 51).PublicKeyMinSig().Bytes()
	pkA, err := G2PointFromCompressed(pkBytes[:])
	if err != nil {
		t.Fatalf("G2PointFromCompressed failed: %v", err)
	}

	s1, s2 := scalarN(13), scalarN(17)
	want := g.Mul(s1).Add(pkA.Mul(s2))

	got, err := MultiScalarMultG2([]G2Point{g, pkA}, [][SeckeyLen]byte{s1, s2})
	if err != nil {
		t.Fatalf("MultiScalarMultG2 failed: %v", err)
	}
	if got != want {
		t.Error("MultiScalarMultG2 disagrees with individual Mul+Add")
	}
}

func TestMultiScalarMultAgreesWithSingleMul(t *testing.T) {
	// A one-point MSM must reduce to plain scalar multiplication.
	g := G1Generator()
	got, err := MultiScalarMultG1([]G1Point{g}, [][SeckeyLen]byte{scalarN(9)})
	if err != nil {
		t.Fatalf("MultiScalarMultG1 failed: %v", err)
	}
	if got != g.Mul(scalarN(9)) {
		t.Error("a one-point MSM disagrees with G1Point.Mul")
	}
}

func TestMultiScalarMultRejectsBadInputs(t *testing.T) {
	g1, g2 := G1Generator(), G2Generator()

	if _, err := MultiScalarMultG1(nil, nil); err == nil {
		t.Error("MultiScalarMultG1 accepted an empty input")
	}
	if _, err := MultiScalarMultG2(nil, nil); err == nil {
		t.Error("MultiScalarMultG2 accepted an empty input")
	}
	if _, err := MultiScalarMultG1([]G1Point{g1, g1}, [][SeckeyLen]byte{scalarN(1)}); err == nil {
		t.Error("MultiScalarMultG1 accepted mismatched points/scalars lengths")
	}
	if _, err := MultiScalarMultG2([]G2Point{g2, g2}, [][SeckeyLen]byte{scalarN(1)}); err == nil {
		t.Error("MultiScalarMultG2 accepted mismatched points/scalars lengths")
	}
}
