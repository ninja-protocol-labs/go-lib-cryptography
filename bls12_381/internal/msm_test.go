package internal

import (
	"bytes"
	"testing"
)

func TestP1sMultPippengerAgreesWithIndividualMults(t *testing.T) {
	g := P1AffineGenerator()
	skA := Keygen(bytes.Repeat([]byte{0x41}, 32), nil)
	pkACompressed := SkToPkInG1Compressed(&skA)
	pkA, _ := P1Uncompress(&pkACompressed)

	s1 := scalarN(t, 7)
	s2 := scalarN(t, 11)

	// sum_i scalars[i]*points[i], computed the slow way via P1Mult + P1Add.
	want1 := P1Mult(&g, s1[:], 256)
	want2 := P1Mult(&pkA, s2[:], 256)
	want := P1Add(&want1, &want2)

	points := append(append([]byte{}, g[:]...), pkA[:]...)
	scalars := append(append([]byte{}, s1[:]...), s2[:]...)
	scratch := make([]byte, P1sMultPippengerScratchSizeof(2))
	got := P1sMultPippenger(points, scalars, 256, scratch)

	if got != want {
		t.Error("P1sMultPippenger disagrees with individual P1Mult+P1Add — scalar convention mismatch")
	}
}

func TestP1sMultPippengerSinglePoint(t *testing.T) {
	// The npoints==1 case exercises blst's own single-point fallback path
	// specifically (see shim_p1s_mult_pippenger's doc comment).
	g := P1AffineGenerator()
	s := scalarN(t, 5)

	want := P1Mult(&g, s[:], 256)

	scratch := make([]byte, P1sMultPippengerScratchSizeof(1))
	got := P1sMultPippenger(g[:], s[:], 256, scratch)

	if got != want {
		t.Error("P1sMultPippenger([g], [5]) != P1Mult(g, 5)")
	}
}

func TestP2sMultPippengerAgreesWithIndividualMults(t *testing.T) {
	g := P2AffineGenerator()
	skA := Keygen(bytes.Repeat([]byte{0x42}, 32), nil)
	pkACompressed := SkToPkInG2Compressed(&skA)
	pkA, _ := P2Uncompress(&pkACompressed)

	s1 := scalarN(t, 13)
	s2 := scalarN(t, 17)

	want1 := P2Mult(&g, s1[:], 256)
	want2 := P2Mult(&pkA, s2[:], 256)
	want := P2Add(&want1, &want2)

	points := append(append([]byte{}, g[:]...), pkA[:]...)
	scalars := append(append([]byte{}, s1[:]...), s2[:]...)
	scratch := make([]byte, P2sMultPippengerScratchSizeof(2))
	got := P2sMultPippenger(points, scalars, 256, scratch)

	if got != want {
		t.Error("P2sMultPippenger disagrees with individual P2Mult+P2Add — scalar convention mismatch")
	}
}

func TestMsmFuncsAllocs(t *testing.T) {
	g := P1AffineGenerator()
	s := scalarN(t, 5)
	points := append([]byte{}, g[:]...)
	scalars := append([]byte{}, s[:]...)
	scratch := make([]byte, P1sMultPippengerScratchSizeof(1))

	allocs := testing.AllocsPerRun(1000, func() {
		P1sMultPippenger(points, scalars, 256, scratch)
	})
	if allocs != 0 {
		t.Errorf("P1sMultPippenger allocated %v times per run, want 0", allocs)
	}
}
