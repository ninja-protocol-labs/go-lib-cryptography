package internal

import (
	"bytes"
	"testing"
)

func TestKeygenIsDeterministic(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x01}, 32)
	sk1 := Keygen(ikm, nil)
	sk2 := Keygen(ikm, nil)
	if sk1 != sk2 {
		t.Error("Keygen produced two different scalars for the same IKM")
	}
	if sk1 == ([32]byte{}) {
		t.Error("Keygen produced the zero scalar")
	}
}

func TestKeygenDiffersByIKM(t *testing.T) {
	ikm1 := bytes.Repeat([]byte{0x01}, 32)
	ikm2 := bytes.Repeat([]byte{0x02}, 32)
	sk1 := Keygen(ikm1, nil)
	sk2 := Keygen(ikm2, nil)
	if sk1 == sk2 {
		t.Error("Keygen produced the same scalar for two different IKMs")
	}
}

func TestKeygenDiffersByInfo(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x01}, 32)
	sk1 := Keygen(ikm, []byte("info-a"))
	sk2 := Keygen(ikm, []byte("info-b"))
	if sk1 == sk2 {
		t.Error("Keygen produced the same scalar for two different info strings")
	}
}

func TestKeygenAllocs(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x01}, 32)
	allocs := testing.AllocsPerRun(1000, func() {
		Keygen(ikm, nil)
	})
	if allocs != 0 {
		t.Errorf("Keygen allocated %v times per call, want 0", allocs)
	}
}

func TestSkCheck(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x01}, 32)
	sk := Keygen(ikm, nil)
	if !SkCheck(&sk) {
		t.Error("SkCheck rejected a key produced by Keygen")
	}

	var zero [ScalarLen]byte
	if SkCheck(&zero) {
		t.Error("SkCheck accepted the zero scalar")
	}

	// Larger than the BLS12-381 subgroup order (~2^255) — not a usable
	// scalar at all, let alone in range.
	var tooBig [ScalarLen]byte
	for i := range tooBig {
		tooBig[i] = 0xff
	}
	if SkCheck(&tooBig) {
		t.Error("SkCheck accepted an out-of-range scalar")
	}
}

func TestScalarFromBEBytesRoundTrip(t *testing.T) {
	five := scalarN(t, 5)
	out, ok := ScalarFromBEBytes(five[:])
	if !ok {
		t.Fatal("ScalarFromBEBytes failed for a valid in-range value")
	}
	if out != five {
		t.Errorf("ScalarFromBEBytes(5) = %x, want %x", out, five)
	}
}

func TestScalarFromBEBytesRejectsEmpty(t *testing.T) {
	if _, ok := ScalarFromBEBytes(nil); ok {
		t.Error("ScalarFromBEBytes accepted empty input")
	}
}

func TestSkAddSubRoundTrip(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x02}, 32)
	a := Keygen(ikm, nil)
	b := scalarN(t, 7)

	sum, ok := SkAdd(&a, &b)
	if !ok {
		t.Fatal("SkAdd failed")
	}
	back, ok := SkSub(&sum, &b)
	if !ok {
		t.Fatal("SkSub failed")
	}
	if back != a {
		t.Errorf("(a + b) - b = %x, want %x", back, a)
	}
}

func TestSkSubToZeroRejected(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x03}, 32)
	a := Keygen(ikm, nil)
	if _, ok := SkSub(&a, &a); ok {
		t.Error("SkSub(a, a) succeeded, want a rejected zero result")
	}
}

func TestSkMulByOne(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x04}, 32)
	a := Keygen(ikm, nil)
	one := scalarOne(t)
	out, ok := SkMul(&a, &one)
	if !ok {
		t.Fatal("SkMul failed")
	}
	if out != a {
		t.Errorf("a * 1 = %x, want %x", out, a)
	}
}

func TestSkInverse(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x05}, 32)
	a := Keygen(ikm, nil)
	one := scalarOne(t)
	inv := SkInverse(&a)
	product, ok := SkMul(&a, &inv)
	if !ok {
		t.Fatal("SkMul(a, inverse(a)) failed")
	}
	if product != one {
		t.Errorf("a * inverse(a) = %x, want 1 (%x)", product, one)
	}
}

func TestSkToPkInG1IsDeterministicAndUnique(t *testing.T) {
	a := Keygen(bytes.Repeat([]byte{0x06}, 32), nil)
	b := Keygen(bytes.Repeat([]byte{0x07}, 32), nil)

	compA1 := SkToPkInG1Compressed(&a)
	compA2 := SkToPkInG1Compressed(&a)
	if compA1 != compA2 {
		t.Error("SkToPkInG1Compressed is not deterministic")
	}
	compB := SkToPkInG1Compressed(&b)
	if compA1 == compB {
		t.Error("SkToPkInG1Compressed produced the same key for two different scalars")
	}

	serA := SkToPkInG1Serialized(&a)
	if bytes.Equal(serA[:], make([]byte, P1SerializedLen)) {
		t.Error("SkToPkInG1Serialized produced an all-zero point")
	}
}

func TestSkToPkInG2IsDeterministicAndUnique(t *testing.T) {
	a := Keygen(bytes.Repeat([]byte{0x08}, 32), nil)
	b := Keygen(bytes.Repeat([]byte{0x09}, 32), nil)

	compA1 := SkToPkInG2Compressed(&a)
	compA2 := SkToPkInG2Compressed(&a)
	if compA1 != compA2 {
		t.Error("SkToPkInG2Compressed is not deterministic")
	}
	compB := SkToPkInG2Compressed(&b)
	if compA1 == compB {
		t.Error("SkToPkInG2Compressed produced the same key for two different scalars")
	}

	serA := SkToPkInG2Serialized(&a)
	if bytes.Equal(serA[:], make([]byte, P2SerializedLen)) {
		t.Error("SkToPkInG2Serialized produced an all-zero point")
	}
}

func TestKeyFuncsAllocs(t *testing.T) {
	sk := Keygen(bytes.Repeat([]byte{0x0a}, 32), nil)
	one := scalarOne(t)

	allocs := testing.AllocsPerRun(1000, func() {
		SkCheck(&sk)
		_, _ = ScalarFromBEBytes(sk[:])
		_, _ = SkAdd(&sk, &one)
		_, _ = SkSub(&sk, &one)
		_, _ = SkMul(&sk, &one)
		SkInverse(&sk)
		SkToPkInG1Compressed(&sk)
		SkToPkInG1Serialized(&sk)
		SkToPkInG2Compressed(&sk)
		SkToPkInG2Serialized(&sk)
	})
	if allocs != 0 {
		t.Errorf("key functions allocated %v times per run, want 0", allocs)
	}
}
