package bls12381

import "testing"

func TestMultiScalarMultG1AgreesWithIndividualMuls(t *testing.T) {
	g := G1Generator()
	priv := privKeyN(t, 50)
	pkA := G1Point(priv.PublicKeyMinPk().point)

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
	priv := privKeyN(t, 51)
	pkA := G2Point(priv.PublicKeyMinSig().point)

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

func TestMultiScalarMultG1RejectsEmpty(t *testing.T) {
	if _, err := MultiScalarMultG1(nil, nil); err == nil {
		t.Error("MultiScalarMultG1 accepted an empty input")
	}
}

func TestMultiScalarMultG1RejectsLengthMismatch(t *testing.T) {
	g := G1Generator()
	if _, err := MultiScalarMultG1([]G1Point{g, g}, [][SeckeyLen]byte{scalarN(1)}); err == nil {
		t.Error("MultiScalarMultG1 accepted mismatched points/scalars lengths")
	}
}

func TestMultiScalarMultAgreesWithSingleMul(t *testing.T) {
	// A one-point MSM must reduce to plain scalar multiplication. A scalar
	// of the wrong width is no longer possible to pass — it is a type
	// error now, not a runtime check.
	g := G1Generator()
	got, err := MultiScalarMultG1([]G1Point{g}, [][SeckeyLen]byte{scalarN(9)})
	if err != nil {
		t.Fatalf("MultiScalarMultG1 failed: %v", err)
	}
	if got != g.Mul(scalarN(9)) {
		t.Error("a one-point MSM disagrees with G1Point.Mul")
	}
}
