package bn254

import "testing"

func TestMultiScalarMultG1AgreesWithIndividualMuls(t *testing.T) {
	g := G1Generator()
	pkBytes := g1PointN(t, 50).Bytes()
	pkA, err := G1PointFromCompressed(pkBytes[:])
	if err != nil {
		t.Fatalf("G1PointFromCompressed failed: %v", err)
	}

	s1, s2 := scalarArrN(t, 7), scalarArrN(t, 11)
	want := g.Mul(s1).Add(pkA.Mul(s2))

	got, err := MultiScalarMultG1([]G1Point{g, pkA}, [][ScalarLen]byte{s1, s2})
	if err != nil {
		t.Fatalf("MultiScalarMultG1 failed: %v", err)
	}
	if got != want {
		t.Error("MultiScalarMultG1 disagrees with individual Mul+Add")
	}
}

func TestMultiScalarMultG2AgreesWithIndividualMuls(t *testing.T) {
	g := G2Generator()
	pkBytes := g2PointN(t, 51).Bytes()
	pkA, err := G2PointFromCompressed(pkBytes[:])
	if err != nil {
		t.Fatalf("G2PointFromCompressed failed: %v", err)
	}

	s1, s2 := scalarArrN(t, 13), scalarArrN(t, 17)
	want := g.Mul(s1).Add(pkA.Mul(s2))

	got, err := MultiScalarMultG2([]G2Point{g, pkA}, [][ScalarLen]byte{s1, s2})
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
	got, err := MultiScalarMultG1([]G1Point{g}, [][ScalarLen]byte{scalarArrN(t, 9)})
	if err != nil {
		t.Fatalf("MultiScalarMultG1 failed: %v", err)
	}
	if got != g.Mul(scalarArrN(t, 9)) {
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
	if _, err := MultiScalarMultG1([]G1Point{g1, g1}, [][ScalarLen]byte{scalarArrN(t, 1)}); err == nil {
		t.Error("MultiScalarMultG1 accepted mismatched points/scalars lengths")
	}
	if _, err := MultiScalarMultG2([]G2Point{g2, g2}, [][ScalarLen]byte{scalarArrN(t, 1)}); err == nil {
		t.Error("MultiScalarMultG2 accepted mismatched points/scalars lengths")
	}
}
