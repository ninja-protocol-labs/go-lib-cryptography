package internal

import "testing"

func TestHashToG1IsDeterministicAndOnCurve(t *testing.T) {
	a := HashToG1(testMsg, testDst, nil)
	b := HashToG1(testMsg, testDst, nil)
	if a != b {
		t.Error("HashToG1 is not deterministic for the same inputs")
	}
	if !P1AffineOnCurve(&a) {
		t.Error("HashToG1's result is not on-curve")
	}
	if !P1AffineInG1(&a) {
		t.Error("HashToG1's result is not in G1")
	}
}

func TestHashToG1VariesWithInputs(t *testing.T) {
	base := HashToG1(testMsg, testDst, nil)

	if diffMsg := HashToG1([]byte("a different message"), testDst, nil); diffMsg == base {
		t.Error("HashToG1 produced the same point for two different messages")
	}
	if diffDst := HashToG1(testMsg, []byte("a different DST"), nil); diffDst == base {
		t.Error("HashToG1 produced the same point for two different DSTs")
	}
	if diffAug := HashToG1(testMsg, testDst, []byte("aug")); diffAug == base {
		t.Error("HashToG1 produced the same point with and without an aug prefix")
	}
}

func TestHashToG1AcceptsEmptyMessage(t *testing.T) {
	p := HashToG1(nil, testDst, nil)
	if !P1AffineOnCurve(&p) {
		t.Error("HashToG1(nil, ...) is not on-curve")
	}
}

func TestEncodeToG1IsDeterministicAndOnCurve(t *testing.T) {
	a := EncodeToG1(testMsg, testDst, nil)
	b := EncodeToG1(testMsg, testDst, nil)
	if a != b {
		t.Error("EncodeToG1 is not deterministic for the same inputs")
	}
	if !P1AffineOnCurve(&a) {
		t.Error("EncodeToG1's result is not on-curve")
	}
	if !P1AffineInG1(&a) {
		t.Error("EncodeToG1's result is not in G1")
	}
}

func TestHashToG1AndEncodeToG1Differ(t *testing.T) {
	// Different maps-to-curve constructions (RO vs. NU) — same inputs must
	// not collide.
	if HashToG1(testMsg, testDst, nil) == EncodeToG1(testMsg, testDst, nil) {
		t.Error("HashToG1 and EncodeToG1 produced the same point for the same inputs")
	}
}

func TestHashToG2IsDeterministicAndOnCurve(t *testing.T) {
	a := HashToG2(testMsg, testDst, nil)
	b := HashToG2(testMsg, testDst, nil)
	if a != b {
		t.Error("HashToG2 is not deterministic for the same inputs")
	}
	if !P2AffineOnCurve(&a) {
		t.Error("HashToG2's result is not on-curve")
	}
	if !P2AffineInG2(&a) {
		t.Error("HashToG2's result is not in G2")
	}
}

func TestHashToG2VariesWithInputs(t *testing.T) {
	base := HashToG2(testMsg, testDst, nil)

	if diffMsg := HashToG2([]byte("a different message"), testDst, nil); diffMsg == base {
		t.Error("HashToG2 produced the same point for two different messages")
	}
	if diffDst := HashToG2(testMsg, []byte("a different DST"), nil); diffDst == base {
		t.Error("HashToG2 produced the same point for two different DSTs")
	}
	if diffAug := HashToG2(testMsg, testDst, []byte("aug")); diffAug == base {
		t.Error("HashToG2 produced the same point with and without an aug prefix")
	}
}

func TestHashToG2AcceptsEmptyMessage(t *testing.T) {
	p := HashToG2(nil, testDst, nil)
	if !P2AffineOnCurve(&p) {
		t.Error("HashToG2(nil, ...) is not on-curve")
	}
}

func TestEncodeToG2IsDeterministicAndOnCurve(t *testing.T) {
	a := EncodeToG2(testMsg, testDst, nil)
	b := EncodeToG2(testMsg, testDst, nil)
	if a != b {
		t.Error("EncodeToG2 is not deterministic for the same inputs")
	}
	if !P2AffineOnCurve(&a) {
		t.Error("EncodeToG2's result is not on-curve")
	}
	if !P2AffineInG2(&a) {
		t.Error("EncodeToG2's result is not in G2")
	}
}

func TestHashToG2AndEncodeToG2Differ(t *testing.T) {
	if HashToG2(testMsg, testDst, nil) == EncodeToG2(testMsg, testDst, nil) {
		t.Error("HashToG2 and EncodeToG2 produced the same point for the same inputs")
	}
}

func TestHashFuncsAllocs(t *testing.T) {
	allocs := testing.AllocsPerRun(1000, func() {
		HashToG1(testMsg, testDst, nil)
		EncodeToG1(testMsg, testDst, nil)
		HashToG2(testMsg, testDst, nil)
		EncodeToG2(testMsg, testDst, nil)
	})
	if allocs != 0 {
		t.Errorf("hash-to-curve functions allocated %v times per run, want 0", allocs)
	}
}
