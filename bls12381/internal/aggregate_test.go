package internal

import (
	"bytes"
	"testing"
)

func TestP1sAggregateCompressedAgreesWithAffine(t *testing.T) {
	skA := Keygen(bytes.Repeat([]byte{0x21}, 32), nil)
	skB := Keygen(bytes.Repeat([]byte{0x22}, 32), nil)
	compA := SkToPkInG1Compressed(&skA)
	compB := SkToPkInG1Compressed(&skB)
	affA, _ := P1Uncompress(&compA)
	affB, _ := P1Uncompress(&compB)

	compressed := append(append([]byte{}, compA[:]...), compB[:]...)
	viaCompressed, code := P1sAggregateCompressed(compressed)
	if code != ErrSuccess {
		t.Fatalf("P1sAggregateCompressed failed: code %d", code)
	}

	affine := append(append([]byte{}, affA[:]...), affB[:]...)
	viaAffine, code := P1sAggregateAffine(affine)
	if code != ErrSuccess {
		t.Fatalf("P1sAggregateAffine failed: code %d", code)
	}

	if viaCompressed != viaAffine {
		t.Error("P1sAggregateCompressed and P1sAggregateAffine of the same points disagree")
	}

	// Aggregation is just point addition — the result must equal a
	// manually-added pair.
	added := P1Add(&affA, &affB)
	if viaAffine != added {
		t.Error("P1sAggregateAffine([a, b]) != P1Add(a, b)")
	}
}

func TestP1sAggregateCompressedRejectsEmpty(t *testing.T) {
	if _, code := P1sAggregateCompressed(nil); code == ErrSuccess {
		t.Error("P1sAggregateCompressed accepted an empty point list")
	}
}

func TestP1sAggregateCompressedRejectsGarbage(t *testing.T) {
	garbage := bytes.Repeat([]byte{0xff}, P1CompressedLen)
	if _, code := P1sAggregateCompressed(garbage); code == ErrSuccess {
		t.Error("P1sAggregateCompressed accepted a garbage point")
	}
}

func TestP2sAggregateCompressedAgreesWithAffine(t *testing.T) {
	skA := Keygen(bytes.Repeat([]byte{0x23}, 32), nil)
	skB := Keygen(bytes.Repeat([]byte{0x24}, 32), nil)
	compA := SkToPkInG2Compressed(&skA)
	compB := SkToPkInG2Compressed(&skB)
	affA, _ := P2Uncompress(&compA)
	affB, _ := P2Uncompress(&compB)

	compressed := append(append([]byte{}, compA[:]...), compB[:]...)
	viaCompressed, code := P2sAggregateCompressed(compressed)
	if code != ErrSuccess {
		t.Fatalf("P2sAggregateCompressed failed: code %d", code)
	}

	affine := append(append([]byte{}, affA[:]...), affB[:]...)
	viaAffine, code := P2sAggregateAffine(affine)
	if code != ErrSuccess {
		t.Fatalf("P2sAggregateAffine failed: code %d", code)
	}

	if viaCompressed != viaAffine {
		t.Error("P2sAggregateCompressed and P2sAggregateAffine of the same points disagree")
	}

	added := P2Add(&affA, &affB)
	if viaAffine != added {
		t.Error("P2sAggregateAffine([a, b]) != P2Add(a, b)")
	}
}

func TestP2sAggregateCompressedRejectsEmpty(t *testing.T) {
	if _, code := P2sAggregateCompressed(nil); code == ErrSuccess {
		t.Error("P2sAggregateCompressed accepted an empty point list")
	}
}

func TestAggregateFuncsAllocs(t *testing.T) {
	skA := Keygen(bytes.Repeat([]byte{0x25}, 32), nil)
	skB := Keygen(bytes.Repeat([]byte{0x26}, 32), nil)
	compA := SkToPkInG1Compressed(&skA)
	compB := SkToPkInG1Compressed(&skB)
	affA, _ := P1Uncompress(&compA)
	affB, _ := P1Uncompress(&compB)
	compressed := append(append([]byte{}, compA[:]...), compB[:]...)
	affine := append(append([]byte{}, affA[:]...), affB[:]...)

	allocs := testing.AllocsPerRun(1000, func() {
		_, _ = P1sAggregateCompressed(compressed)
		_, _ = P1sAggregateAffine(affine)
	})
	if allocs != 0 {
		t.Errorf("aggregate functions allocated %v times per run, want 0", allocs)
	}
}
