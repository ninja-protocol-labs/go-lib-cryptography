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
