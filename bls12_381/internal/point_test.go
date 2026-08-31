package internal

import (
	"bytes"
	"testing"
)

func TestP1RoundTrip(t *testing.T) {
	sk := Keygen(bytes.Repeat([]byte{0x01}, 32), nil)
	compressed := SkToPkInG1Compressed(&sk)
	serialized := SkToPkInG1Serialized(&sk)

	fromCompressed, code := P1Uncompress(&compressed)
	if code != ErrSuccess {
		t.Fatalf("P1Uncompress failed: code %d", code)
	}
	fromSerialized, code := P1Deserialize(&serialized)
	if code != ErrSuccess {
		t.Fatalf("P1Deserialize failed: code %d", code)
	}
	if fromCompressed != fromSerialized {
		t.Error("P1Uncompress and P1Deserialize of the same key produced different affine points")
	}

	if P1AffineCompress(&fromCompressed) != compressed {
		t.Error("P1AffineCompress(P1Uncompress(x)) != x")
	}
	if P1AffineSerialize(&fromSerialized) != serialized {
		t.Error("P1AffineSerialize(P1Deserialize(x)) != x")
	}
}

func TestP1UncompressRejectsGarbage(t *testing.T) {
	var garbage [P1CompressedLen]byte
	for i := range garbage {
		garbage[i] = 0xff
	}
	if _, code := P1Uncompress(&garbage); code == ErrSuccess {
		t.Error("P1Uncompress accepted garbage input")
	}
}

func TestP1AffineOnCurveAndInG1(t *testing.T) {
	sk := Keygen(bytes.Repeat([]byte{0x02}, 32), nil)
	compressed := SkToPkInG1Compressed(&sk)
	p, code := P1Uncompress(&compressed)
	if code != ErrSuccess {
		t.Fatalf("P1Uncompress failed: code %d", code)
	}
	if !P1AffineOnCurve(&p) {
		t.Error("a real public key is not reported on-curve")
	}
	if !P1AffineInG1(&p) {
		t.Error("a real public key is not reported in G1")
	}
	if P1AffineIsInf(&p) {
		t.Error("a real public key is reported as the point at infinity")
	}
}

func TestP1AffineGeneratorIsOnCurveAndInG1(t *testing.T) {
	g := P1AffineGenerator()
	if !P1AffineOnCurve(&g) {
		t.Error("the G1 generator is not reported on-curve")
	}
	if !P1AffineInG1(&g) {
		t.Error("the G1 generator is not reported in G1")
	}
}

func TestP1AffineIsEqual(t *testing.T) {
	skA := Keygen(bytes.Repeat([]byte{0x03}, 32), nil)
	skB := Keygen(bytes.Repeat([]byte{0x04}, 32), nil)
	a := SkToPkInG1Compressed(&skA)
	b := SkToPkInG1Compressed(&skB)
	pa, _ := P1Uncompress(&a)
	pb, _ := P1Uncompress(&b)

	if !P1AffineIsEqual(&pa, &pa) {
		t.Error("P1AffineIsEqual is false comparing a point to itself")
	}
	if P1AffineIsEqual(&pa, &pb) {
		t.Error("P1AffineIsEqual is true for two different points")
	}
}

func TestP1ArithmeticAgreesWithScalarMult(t *testing.T) {
	// 1*G + 1*G must equal 2*G, both via doubling/addition and via a direct
	// scalar multiplication — the actual algebraic property these
	// functions are supposed to satisfy, not just "doesn't crash".
	g := P1AffineGenerator()

	doubled := P1Double(&g)
	added := P1Add(&g, &g)
	if doubled != added {
		t.Error("P1Double(G) != P1Add(G, G)")
	}

	two := scalarN(t, 2)
	mult := P1Mult(&g, two[:], 256)
	if mult != doubled {
		t.Error("P1Mult(G, 2) != P1Double(G)")
	}
}

func TestP1Neg(t *testing.T) {
	g := P1AffineGenerator()
	negG := P1Neg(&g)
	if P1AffineIsEqual(&g, &negG) {
		t.Error("P1Neg(G) == G")
	}
	// G + (-G) must be the point at infinity.
	sum := P1Add(&g, &negG)
	if !P1AffineIsInf(&sum) {
		t.Error("G + (-G) is not the point at infinity")
	}
}

func TestP1FuncsAllocs(t *testing.T) {
	sk := Keygen(bytes.Repeat([]byte{0x05}, 32), nil)
	compressed := SkToPkInG1Compressed(&sk)
	serialized := SkToPkInG1Serialized(&sk)
	p, _ := P1Uncompress(&compressed)
	g := P1AffineGenerator()
	two := scalarN(t, 2)

	allocs := testing.AllocsPerRun(1000, func() {
		_, _ = P1Uncompress(&compressed)
		_, _ = P1Deserialize(&serialized)
		P1AffineCompress(&p)
		P1AffineSerialize(&p)
		P1AffineOnCurve(&p)
		P1AffineInG1(&p)
		P1AffineIsInf(&p)
		P1AffineIsEqual(&p, &g)
		P1AffineGenerator()
		P1Add(&p, &g)
		P1Double(&p)
		P1Mult(&g, two[:], 256)
		P1Neg(&p)
	})
	if allocs != 0 {
		t.Errorf("G1 point functions allocated %v times per run, want 0", allocs)
	}
}

// G2: the same coverage as G1 above, at G2's sizes — no need to re-derive
// the algebraic properties, just confirm they hold at the other size too.

func TestP2RoundTrip(t *testing.T) {
	sk := Keygen(bytes.Repeat([]byte{0x06}, 32), nil)
	compressed := SkToPkInG2Compressed(&sk)
	serialized := SkToPkInG2Serialized(&sk)

	fromCompressed, code := P2Uncompress(&compressed)
	if code != ErrSuccess {
		t.Fatalf("P2Uncompress failed: code %d", code)
	}
	fromSerialized, code := P2Deserialize(&serialized)
	if code != ErrSuccess {
		t.Fatalf("P2Deserialize failed: code %d", code)
	}
	if fromCompressed != fromSerialized {
		t.Error("P2Uncompress and P2Deserialize of the same key produced different affine points")
	}

	if P2AffineCompress(&fromCompressed) != compressed {
		t.Error("P2AffineCompress(P2Uncompress(x)) != x")
	}
	if P2AffineSerialize(&fromSerialized) != serialized {
		t.Error("P2AffineSerialize(P2Deserialize(x)) != x")
	}
}

func TestP2UncompressRejectsGarbage(t *testing.T) {
	var garbage [P2CompressedLen]byte
	for i := range garbage {
		garbage[i] = 0xff
	}
	if _, code := P2Uncompress(&garbage); code == ErrSuccess {
		t.Error("P2Uncompress accepted garbage input")
	}
}

func TestP2AffineOnCurveAndInG2(t *testing.T) {
	sk := Keygen(bytes.Repeat([]byte{0x07}, 32), nil)
	compressed := SkToPkInG2Compressed(&sk)
	p, code := P2Uncompress(&compressed)
	if code != ErrSuccess {
		t.Fatalf("P2Uncompress failed: code %d", code)
	}
	if !P2AffineOnCurve(&p) {
		t.Error("a real public key is not reported on-curve")
	}
	if !P2AffineInG2(&p) {
		t.Error("a real public key is not reported in G2")
	}
	if P2AffineIsInf(&p) {
		t.Error("a real public key is reported as the point at infinity")
	}
}

func TestP2AffineGeneratorIsOnCurveAndInG2(t *testing.T) {
	g := P2AffineGenerator()
	if !P2AffineOnCurve(&g) {
		t.Error("the G2 generator is not reported on-curve")
	}
	if !P2AffineInG2(&g) {
		t.Error("the G2 generator is not reported in G2")
	}
}

func TestP2AffineIsEqual(t *testing.T) {
	skA := Keygen(bytes.Repeat([]byte{0x08}, 32), nil)
	skB := Keygen(bytes.Repeat([]byte{0x09}, 32), nil)
	a := SkToPkInG2Compressed(&skA)
	b := SkToPkInG2Compressed(&skB)
	pa, _ := P2Uncompress(&a)
	pb, _ := P2Uncompress(&b)

	if !P2AffineIsEqual(&pa, &pa) {
		t.Error("P2AffineIsEqual is false comparing a point to itself")
	}
	if P2AffineIsEqual(&pa, &pb) {
		t.Error("P2AffineIsEqual is true for two different points")
	}
}

func TestP2ArithmeticAgreesWithScalarMult(t *testing.T) {
	g := P2AffineGenerator()

	doubled := P2Double(&g)
	added := P2Add(&g, &g)
	if doubled != added {
		t.Error("P2Double(G) != P2Add(G, G)")
	}

	two := scalarN(t, 2)
	mult := P2Mult(&g, two[:], 256)
	if mult != doubled {
		t.Error("P2Mult(G, 2) != P2Double(G)")
	}
}

func TestP2Neg(t *testing.T) {
	g := P2AffineGenerator()
	negG := P2Neg(&g)
	if P2AffineIsEqual(&g, &negG) {
		t.Error("P2Neg(G) == G")
	}
	sum := P2Add(&g, &negG)
	if !P2AffineIsInf(&sum) {
		t.Error("G + (-G) is not the point at infinity")
	}
}

func TestP2FuncsAllocs(t *testing.T) {
	sk := Keygen(bytes.Repeat([]byte{0x0a}, 32), nil)
	compressed := SkToPkInG2Compressed(&sk)
	serialized := SkToPkInG2Serialized(&sk)
	p, _ := P2Uncompress(&compressed)
	g := P2AffineGenerator()
	two := scalarN(t, 2)

	allocs := testing.AllocsPerRun(1000, func() {
		_, _ = P2Uncompress(&compressed)
		_, _ = P2Deserialize(&serialized)
		P2AffineCompress(&p)
		P2AffineSerialize(&p)
		P2AffineOnCurve(&p)
		P2AffineInG2(&p)
		P2AffineIsInf(&p)
		P2AffineIsEqual(&p, &g)
		P2AffineGenerator()
		P2Add(&p, &g)
		P2Double(&p)
		P2Mult(&g, two[:], 256)
		P2Neg(&p)
	})
	if allocs != 0 {
		t.Errorf("G2 point functions allocated %v times per run, want 0", allocs)
	}
}
