package bls12381

import "testing"

func TestMultiScalarMultG1AgreesWithIndividualMuls(t *testing.T) {
	g := G1Generator()
	priv := privKeyN(t, 50)
	pkA := G1Point(priv.PublicKeyMinPk().point)

	s1 := make([]byte, 32)
	s1[31] = 7
	s2 := make([]byte, 32)
	s2[31] = 11

	want := g.Mul(s1, 256).Add(pkA.Mul(s2, 256))

	got, err := MultiScalarMultG1([]G1Point{g, pkA}, [][]byte{s1, s2}, 256)
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

	s1 := make([]byte, 32)
	s1[31] = 13
	s2 := make([]byte, 32)
	s2[31] = 17

	want := g.Mul(s1, 256).Add(pkA.Mul(s2, 256))

	got, err := MultiScalarMultG2([]G2Point{g, pkA}, [][]byte{s1, s2}, 256)
	if err != nil {
		t.Fatalf("MultiScalarMultG2 failed: %v", err)
	}
	if got != want {
		t.Error("MultiScalarMultG2 disagrees with individual Mul+Add")
	}
}

func TestMultiScalarMultG1RejectsEmpty(t *testing.T) {
	if _, err := MultiScalarMultG1(nil, nil, 256); err == nil {
		t.Error("MultiScalarMultG1 accepted an empty input")
	}
}

func TestMultiScalarMultG1RejectsLengthMismatch(t *testing.T) {
	g := G1Generator()
	s := make([]byte, 32)
	if _, err := MultiScalarMultG1([]G1Point{g, g}, [][]byte{s}, 256); err == nil {
		t.Error("MultiScalarMultG1 accepted mismatched points/scalars lengths")
	}
}

func TestMultiScalarMultG1RejectsWrongScalarWidth(t *testing.T) {
	g := G1Generator()
	shortScalar := make([]byte, 16) // stride for nbits=256 is 32 bytes
	if _, err := MultiScalarMultG1([]G1Point{g}, [][]byte{shortScalar}, 256); err == nil {
		t.Error("MultiScalarMultG1 accepted a scalar of the wrong width for nbits")
	}
}
