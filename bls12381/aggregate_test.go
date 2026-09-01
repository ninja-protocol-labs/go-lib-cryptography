package bls12381

import "testing"

func TestAggregatePublicKeysMinPkAgreesWithPointAdd(t *testing.T) {
	privA := privKeyN(t, 23)
	privB := privKeyN(t, 24)
	pubA := privA.PublicKeyMinPk()
	pubB := privB.PublicKeyMinPk()

	agg, err := AggregatePublicKeysMinPk([]*PublicKeyMinPk{pubA, pubB})
	if err != nil {
		t.Fatalf("AggregatePublicKeysMinPk failed: %v", err)
	}

	// The sum of two private keys' public keys must equal the public key
	// of the summed private key — sk isn't summed via addition mod r by
	// this package's public API, so this is checked the other direction:
	// order shouldn't matter.
	aggReversed, err := AggregatePublicKeysMinPk([]*PublicKeyMinPk{pubB, pubA})
	if err != nil {
		t.Fatalf("AggregatePublicKeysMinPk (reversed) failed: %v", err)
	}
	if !agg.Equal(aggReversed) {
		t.Error("AggregatePublicKeysMinPk is not order-independent")
	}
}

func TestAggregatePublicKeysMinPkRejectsEmpty(t *testing.T) {
	if _, err := AggregatePublicKeysMinPk(nil); err == nil {
		t.Error("AggregatePublicKeysMinPk accepted an empty list")
	}
}

func TestAggregatePublicKeysMinSigRejectsEmpty(t *testing.T) {
	if _, err := AggregatePublicKeysMinSig(nil); err == nil {
		t.Error("AggregatePublicKeysMinSig accepted an empty list")
	}
}

func TestAggregateSignaturesMinPkRoundTrip(t *testing.T) {
	privA := privKeyN(t, 25)
	privB := privKeyN(t, 26)
	pubA := privA.PublicKeyMinPk()
	pubB := privB.PublicKeyMinPk()

	sigA := SignMinPk(privA, testMsg)
	sigB := SignMinPk(privB, testMsg)

	aggSig, err := AggregateSignaturesMinPk([][]byte{sigA[:], sigB[:]})
	if err != nil {
		t.Fatalf("AggregateSignaturesMinPk failed: %v", err)
	}

	if !FastAggregateVerifyMinPk([]*PublicKeyMinPk{pubA, pubB}, testMsg, aggSig[:]) {
		t.Error("FastAggregateVerifyMinPk rejected a genuine aggregated signature")
	}
}

func TestAggregateSignaturesMinSigRoundTrip(t *testing.T) {
	privA := privKeyN(t, 27)
	privB := privKeyN(t, 28)
	pubA := privA.PublicKeyMinSig()
	pubB := privB.PublicKeyMinSig()

	sigA := SignMinSig(privA, testMsg)
	sigB := SignMinSig(privB, testMsg)

	aggSig, err := AggregateSignaturesMinSig([][]byte{sigA[:], sigB[:]})
	if err != nil {
		t.Fatalf("AggregateSignaturesMinSig failed: %v", err)
	}

	if !FastAggregateVerifyMinSig([]*PublicKeyMinSig{pubA, pubB}, testMsg, aggSig[:]) {
		t.Error("FastAggregateVerifyMinSig rejected a genuine aggregated signature")
	}
}

func TestAggregateSignaturesMinPkRejectsEmpty(t *testing.T) {
	if _, err := AggregateSignaturesMinPk(nil); err == nil {
		t.Error("AggregateSignaturesMinPk accepted an empty list")
	}
}

func TestAggregateSignaturesMinPkRejectsWrongLength(t *testing.T) {
	if _, err := AggregateSignaturesMinPk([][]byte{{0x01, 0x02}}); err == nil {
		t.Error("AggregateSignaturesMinPk accepted a wrong-length signature")
	}
}

func TestFastAggregateVerifyMinPkRejectsTamperedSignature(t *testing.T) {
	privA := privKeyN(t, 29)
	privB := privKeyN(t, 30)
	pubA := privA.PublicKeyMinPk()
	pubB := privB.PublicKeyMinPk()

	sigA := SignMinPk(privA, testMsg)
	sigB := SignMinPk(privB, []byte("a different message"))

	aggSig, err := AggregateSignaturesMinPk([][]byte{sigA[:], sigB[:]})
	if err != nil {
		t.Fatalf("AggregateSignaturesMinPk failed: %v", err)
	}
	if FastAggregateVerifyMinPk([]*PublicKeyMinPk{pubA, pubB}, testMsg, aggSig[:]) {
		t.Error("FastAggregateVerifyMinPk accepted a signature aggregated from mismatched messages")
	}
}

func TestAggregateVerifyMinPkDistinctMessages(t *testing.T) {
	privA := privKeyN(t, 31)
	privB := privKeyN(t, 32)
	pubA := privA.PublicKeyMinPk()
	pubB := privB.PublicKeyMinPk()
	msgA := []byte("message A")
	msgB := []byte("message B")

	sigA := SignMinPk(privA, msgA)
	sigB := SignMinPk(privB, msgB)
	aggSig, err := AggregateSignaturesMinPk([][]byte{sigA[:], sigB[:]})
	if err != nil {
		t.Fatalf("AggregateSignaturesMinPk failed: %v", err)
	}

	if !AggregateVerifyMinPk([]*PublicKeyMinPk{pubA, pubB}, [][]byte{msgA, msgB}, aggSig[:]) {
		t.Error("AggregateVerifyMinPk rejected a genuine batch over distinct messages")
	}
	if AggregateVerifyMinPk([]*PublicKeyMinPk{pubA, pubB}, [][]byte{msgB, msgA}, aggSig[:]) {
		t.Error("AggregateVerifyMinPk accepted messages assigned to the wrong signer")
	}
}

func TestAggregateVerifyMinSigDistinctMessages(t *testing.T) {
	privA := privKeyN(t, 33)
	privB := privKeyN(t, 34)
	pubA := privA.PublicKeyMinSig()
	pubB := privB.PublicKeyMinSig()
	msgA := []byte("message A")
	msgB := []byte("message B")

	sigA := SignMinSig(privA, msgA)
	sigB := SignMinSig(privB, msgB)
	aggSig, err := AggregateSignaturesMinSig([][]byte{sigA[:], sigB[:]})
	if err != nil {
		t.Fatalf("AggregateSignaturesMinSig failed: %v", err)
	}

	if !AggregateVerifyMinSig([]*PublicKeyMinSig{pubA, pubB}, [][]byte{msgA, msgB}, aggSig[:]) {
		t.Error("AggregateVerifyMinSig rejected a genuine batch over distinct messages")
	}
	if AggregateVerifyMinSig([]*PublicKeyMinSig{pubA, pubB}, [][]byte{msgB, msgA}, aggSig[:]) {
		t.Error("AggregateVerifyMinSig accepted messages assigned to the wrong signer")
	}
}

func TestAggregateVerifyMinPkRejectsLengthMismatch(t *testing.T) {
	privA := privKeyN(t, 35)
	pubA := privA.PublicKeyMinPk()
	sig := SignMinPk(privA, testMsg)

	if AggregateVerifyMinPk([]*PublicKeyMinPk{pubA}, [][]byte{testMsg, testMsg}, sig[:]) {
		t.Error("AggregateVerifyMinPk accepted mismatched pks/msgs lengths")
	}
}
