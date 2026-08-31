package internal

import (
	"bytes"
	"testing"
)

func TestPairingAggregateAndFinalVerifyPkInG1(t *testing.T) {
	sk := Keygen(bytes.Repeat([]byte{0x31}, 32), nil)
	pkCompressed := SkToPkInG1Compressed(&sk)
	pk, _ := P1Uncompress(&pkCompressed)
	sigCompressed := SignMsgPkInG1(&sk, testMsg, testDst, nil)
	sig, _ := P2Uncompress(&sigCompressed)

	ctx := newPairingCtx(t, true, testDst)
	if code := PairingAggregatePkInG1(ctx, &pk, sig[:], testMsg, nil); code != ErrSuccess {
		t.Fatalf("PairingAggregatePkInG1 failed: code %d", code)
	}
	PairingCommit(ctx)
	if !PairingFinalVerify(ctx, nil) {
		t.Error("PairingFinalVerify rejected a genuine aggregated signature")
	}
}

func TestPairingAggregateRejectsWrongMessage(t *testing.T) {
	sk := Keygen(bytes.Repeat([]byte{0x32}, 32), nil)
	pkCompressed := SkToPkInG1Compressed(&sk)
	pk, _ := P1Uncompress(&pkCompressed)
	sigCompressed := SignMsgPkInG1(&sk, testMsg, testDst, nil)
	sig, _ := P2Uncompress(&sigCompressed)

	ctx := newPairingCtx(t, true, testDst)
	if code := PairingAggregatePkInG1(ctx, &pk, sig[:], []byte("wrong message"), nil); code != ErrSuccess {
		t.Fatalf("PairingAggregatePkInG1 failed: code %d", code)
	}
	PairingCommit(ctx)
	if PairingFinalVerify(ctx, nil) {
		t.Error("PairingFinalVerify accepted a signature over the wrong message")
	}
}

func TestPairingChkNAggrPkInG1(t *testing.T) {
	sk := Keygen(bytes.Repeat([]byte{0x33}, 32), nil)
	pkCompressed := SkToPkInG1Compressed(&sk)
	pk, _ := P1Uncompress(&pkCompressed)
	sigCompressed := SignMsgPkInG1(&sk, testMsg, testDst, nil)
	sig, _ := P2Uncompress(&sigCompressed)

	ctx := newPairingCtx(t, true, testDst)
	if code := PairingChkNAggrPkInG1(ctx, &pk, true, sig[:], true, testMsg, nil); code != ErrSuccess {
		t.Fatalf("PairingChkNAggrPkInG1 failed: code %d", code)
	}
	PairingCommit(ctx)
	if !PairingFinalVerify(ctx, nil) {
		t.Error("PairingFinalVerify rejected a genuine chk_n_aggr signature")
	}
}

func TestPairingMulNAggregateBatch(t *testing.T) {
	// Batch-verify two distinct (pk, sig, msg) triples in one pairing
	// context — the real use case mul_n_ exists for.
	skA := Keygen(bytes.Repeat([]byte{0x34}, 32), nil)
	skB := Keygen(bytes.Repeat([]byte{0x35}, 32), nil)
	msgA := []byte("message A")
	msgB := []byte("message B")

	pkACompressed := SkToPkInG1Compressed(&skA)
	pkA, _ := P1Uncompress(&pkACompressed)
	sigACompressed := SignMsgPkInG1(&skA, msgA, testDst, nil)
	sigA, _ := P2Uncompress(&sigACompressed)

	pkBCompressed := SkToPkInG1Compressed(&skB)
	pkB, _ := P1Uncompress(&pkBCompressed)
	sigBCompressed := SignMsgPkInG1(&skB, msgB, testDst, nil)
	sigB, _ := P2Uncompress(&sigBCompressed)

	scalarA := scalarN(t, 7)
	scalarB := scalarN(t, 11)

	ctx := newPairingCtx(t, true, testDst)
	if code := PairingMulNAggregatePkInG1(ctx, &pkA, sigA[:], scalarA[:], 256, msgA, nil); code != ErrSuccess {
		t.Fatalf("PairingMulNAggregatePkInG1 (A) failed: code %d", code)
	}
	if code := PairingMulNAggregatePkInG1(ctx, &pkB, sigB[:], scalarB[:], 256, msgB, nil); code != ErrSuccess {
		t.Fatalf("PairingMulNAggregatePkInG1 (B) failed: code %d", code)
	}
	PairingCommit(ctx)
	if !PairingFinalVerify(ctx, nil) {
		t.Error("PairingFinalVerify rejected a genuine batch")
	}
}

func TestPairingChkNMulNAggrPkInG1RejectsWrongSig(t *testing.T) {
	skA := Keygen(bytes.Repeat([]byte{0x36}, 32), nil)
	skB := Keygen(bytes.Repeat([]byte{0x37}, 32), nil)
	pkACompressed := SkToPkInG1Compressed(&skA)
	pkA, _ := P1Uncompress(&pkACompressed)
	// Sign msgA with the wrong key (skB) — the batch must fail.
	wrongSigCompressed := SignMsgPkInG1(&skB, testMsg, testDst, nil)
	wrongSig, _ := P2Uncompress(&wrongSigCompressed)

	scalar := scalarN(t, 3)
	ctx := newPairingCtx(t, true, testDst)
	if code := PairingChkNMulNAggrPkInG1(ctx, &pkA, true, wrongSig[:], true, scalar[:], 256, testMsg, nil); code != ErrSuccess {
		t.Fatalf("PairingChkNMulNAggrPkInG1 failed to aggregate: code %d", code)
	}
	PairingCommit(ctx)
	if PairingFinalVerify(ctx, nil) {
		t.Error("PairingFinalVerify accepted a batch with a mismatched signature")
	}
}

func TestPairingMergeAgreesWithSingleContext(t *testing.T) {
	skA := Keygen(bytes.Repeat([]byte{0x38}, 32), nil)
	skB := Keygen(bytes.Repeat([]byte{0x39}, 32), nil)
	msgA := []byte("message A")
	msgB := []byte("message B")

	pkACompressed := SkToPkInG1Compressed(&skA)
	pkA, _ := P1Uncompress(&pkACompressed)
	sigACompressed := SignMsgPkInG1(&skA, msgA, testDst, nil)
	sigA, _ := P2Uncompress(&sigACompressed)

	pkBCompressed := SkToPkInG1Compressed(&skB)
	pkB, _ := P1Uncompress(&pkBCompressed)
	sigBCompressed := SignMsgPkInG1(&skB, msgB, testDst, nil)
	sigB, _ := P2Uncompress(&sigBCompressed)

	// Two separate contexts, each aggregating one triple, then merged —
	// must verify the same as aggregating both into one context directly.
	ctxA := newPairingCtx(t, true, testDst)
	if code := PairingAggregatePkInG1(ctxA, &pkA, sigA[:], msgA, nil); code != ErrSuccess {
		t.Fatalf("PairingAggregatePkInG1 (A) failed: code %d", code)
	}
	PairingCommit(ctxA)

	ctxB := newPairingCtx(t, true, testDst)
	if code := PairingAggregatePkInG1(ctxB, &pkB, sigB[:], msgB, nil); code != ErrSuccess {
		t.Fatalf("PairingAggregatePkInG1 (B) failed: code %d", code)
	}
	PairingCommit(ctxB)

	if code := PairingMerge(ctxA, ctxB); code != ErrSuccess {
		t.Fatalf("PairingMerge failed: code %d", code)
	}
	if !PairingFinalVerify(ctxA, nil) {
		t.Error("PairingFinalVerify rejected a merged pairing context")
	}
}

func TestMillerLoopAgreesWithLinesPrecompute(t *testing.T) {
	g1 := P1AffineGenerator()
	g2 := P2AffineGenerator()

	direct := MillerLoop(&g2, &g1)

	lines := PrecomputeLines(&g2)
	viaLines := MillerLoopLines(&lines, &g1)

	if !Fp12IsEqual(&direct, &viaLines) {
		t.Error("MillerLoop(G2, G1) != MillerLoopLines(PrecomputeLines(G2), G1)")
	}
}

func TestMillerLoopNAgreesWithFp12Mul(t *testing.T) {
	g1 := P1AffineGenerator()
	g2 := P2AffineGenerator()
	skA := Keygen(bytes.Repeat([]byte{0x3a}, 32), nil)
	pkACompressed := SkToPkInG1Compressed(&skA)
	pkA, _ := P1Uncompress(&pkACompressed)

	// Product of two individual Miller loops must equal the batched
	// two-point Miller loop over the same pairs.
	loop1 := MillerLoop(&g2, &g1)
	loop2 := MillerLoop(&g2, &pkA)
	product := Fp12Mul(&loop1, &loop2)

	qs := append(append([]byte{}, g2[:]...), g2[:]...)
	ps := append(append([]byte{}, g1[:]...), pkA[:]...)
	batched := MillerLoopN(qs, ps)

	if !Fp12IsEqual(&product, &batched) {
		t.Error("MillerLoop(q,p1)*MillerLoop(q,p2) != MillerLoopN([q,q],[p1,p2])")
	}
}

func TestAggregatedInG1MatchesPairingFinalVerify(t *testing.T) {
	// gtsig supplied separately (via AggregatedInG1) must verify the same
	// as folding the signature into the context via PairingAggregatePkInG1.
	sk := Keygen(bytes.Repeat([]byte{0x3b}, 32), nil)
	pkCompressed := SkToPkInG1Compressed(&sk)
	pk, _ := P1Uncompress(&pkCompressed)
	sigCompressed := SignMsgPkInG1(&sk, testMsg, testDst, nil)
	sig, _ := P2Uncompress(&sigCompressed)

	gtsig := AggregatedInG2(&sig)

	ctx := newPairingCtx(t, true, testDst)
	if code := PairingAggregatePkInG1(ctx, &pk, nil, testMsg, nil); code != ErrSuccess {
		t.Fatalf("PairingAggregatePkInG1 (pk only) failed: code %d", code)
	}
	PairingCommit(ctx)
	if !PairingFinalVerify(ctx, &gtsig) {
		t.Error("PairingFinalVerify with an externally-supplied gtsig rejected a genuine signature")
	}
}

func TestFp12Algebra(t *testing.T) {
	g1 := P1AffineGenerator()
	g2 := P2AffineGenerator()
	loop := MillerLoop(&g2, &g1)
	f := FinalExp(&loop)

	one := Fp12One()
	if !Fp12IsOne(&one) {
		t.Error("Fp12IsOne(Fp12One()) is false")
	}
	if Fp12IsOne(&f) {
		t.Error("a real final-exponentiated Miller loop result reported as one")
	}
	if !Fp12InGroup(&f) {
		t.Error("a real final-exponentiated Miller loop result reported as not in the GT subgroup")
	}

	sqr := Fp12Sqr(&f)
	mulSelf := Fp12Mul(&f, &f)
	if !Fp12IsEqual(&sqr, &mulSelf) {
		t.Error("Fp12Sqr(f) != Fp12Mul(f, f)")
	}

	inv := Fp12Inverse(&f)
	prod := Fp12Mul(&f, &inv)
	if !Fp12IsEqual(&prod, &one) {
		t.Error("Fp12Mul(f, Fp12Inverse(f)) != Fp12One()")
	}

	if !Fp12FinalVerify(&loop, &loop) {
		t.Error("Fp12FinalVerify(x, x) is false")
	}
}

func TestPairingAndFp12FuncsAllocs(t *testing.T) {
	sk := Keygen(bytes.Repeat([]byte{0x3c}, 32), nil)
	pkCompressed := SkToPkInG1Compressed(&sk)
	pk, _ := P1Uncompress(&pkCompressed)
	sigCompressed := SignMsgPkInG1(&sk, testMsg, testDst, nil)
	sig, _ := P2Uncompress(&sigCompressed)
	g1 := P1AffineGenerator()
	g2 := P2AffineGenerator()
	loop := MillerLoop(&g2, &g1)
	f := FinalExp(&loop)
	lines := PrecomputeLines(&g2)

	// ctx setup/teardown allocates (it's a variable-sized buffer) — only the
	// steady-state per-call operations below are checked for zero allocs.
	ctx := newPairingCtx(t, true, testDst)

	allocs := testing.AllocsPerRun(1000, func() {
		PairingCommit(ctx)
		PairingFinalVerify(ctx, nil)
		MillerLoop(&g2, &g1)
		FinalExp(&loop)
		PrecomputeLines(&g2)
		MillerLoopLines(&lines, &g1)
		Fp12Mul(&f, &f)
		Fp12Sqr(&f)
		Fp12Inverse(&f)
		Fp12One()
		Fp12IsOne(&f)
		Fp12IsEqual(&f, &f)
		Fp12InGroup(&f)
		Fp12FinalVerify(&loop, &loop)
		AggregatedInG1(&pk)
		AggregatedInG2(&sig)
	})
	if allocs != 0 {
		t.Errorf("pairing/fp12 functions allocated %v times per run, want 0", allocs)
	}
}
