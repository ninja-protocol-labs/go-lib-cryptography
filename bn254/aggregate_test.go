package bn254

import "testing"

func TestAggregatePublicKeysMinPkIsOrderIndependent(t *testing.T) {
	a := privKeyN(t, 20).PublicKeyMinPk()
	b := privKeyN(t, 21).PublicKeyMinPk()
	c := privKeyN(t, 22).PublicKeyMinPk()

	ab, err := AggregatePublicKeysMinPk([]*PublicKeyMinPk{a, b, c})
	if err != nil {
		t.Fatalf("AggregatePublicKeysMinPk failed: %v", err)
	}
	ba, err := AggregatePublicKeysMinPk([]*PublicKeyMinPk{c, a, b})
	if err != nil {
		t.Fatalf("AggregatePublicKeysMinPk failed: %v", err)
	}
	if !ab.Equal(ba) {
		t.Error("public key aggregation depends on input order")
	}
}

func TestAggregatePublicKeysMinSigIsOrderIndependent(t *testing.T) {
	a := privKeyN(t, 20).PublicKeyMinSig()
	b := privKeyN(t, 21).PublicKeyMinSig()

	ab, err := AggregatePublicKeysMinSig([]*PublicKeyMinSig{a, b})
	if err != nil {
		t.Fatalf("AggregatePublicKeysMinSig failed: %v", err)
	}
	ba, err := AggregatePublicKeysMinSig([]*PublicKeyMinSig{b, a})
	if err != nil {
		t.Fatalf("AggregatePublicKeysMinSig failed: %v", err)
	}
	if !ab.Equal(ba) {
		t.Error("public key aggregation depends on input order")
	}
}

func TestAggregateRejectsEmptyAndNil(t *testing.T) {
	if _, err := AggregatePublicKeysMinPk(nil); err == nil {
		t.Error("AggregatePublicKeysMinPk accepted an empty set")
	}
	if _, err := AggregatePublicKeysMinSig(nil); err == nil {
		t.Error("AggregatePublicKeysMinSig accepted an empty set")
	}
	if _, err := AggregatePublicKeysMinPk([]*PublicKeyMinPk{nil}); err == nil {
		t.Error("AggregatePublicKeysMinPk accepted a nil key")
	}
	if _, err := AggregateSignaturesMinPk(nil); err == nil {
		t.Error("AggregateSignaturesMinPk accepted an empty set")
	}
	if _, err := AggregateSignaturesMinSig(nil); err == nil {
		t.Error("AggregateSignaturesMinSig accepted an empty set")
	}
}

func TestFastAggregateVerifyMinPk(t *testing.T) {
	privs := []*PrivateKey{privKeyN(t, 23), privKeyN(t, 24), privKeyN(t, 25)}
	pks := make([]*PublicKeyMinPk, len(privs))
	sigs := make([][]byte, len(privs))
	for i, priv := range privs {
		pks[i] = priv.PublicKeyMinPk()
		sig := signMinPk(t, priv, testMsg)
		sigs[i] = sig[:]
	}

	aggSig, err := AggregateSignaturesMinPk(sigs)
	if err != nil {
		t.Fatalf("AggregateSignaturesMinPk failed: %v", err)
	}
	if !FastAggregateVerifyMinPk(pks, testMsg, aggSig[:]) {
		t.Error("FastAggregateVerifyMinPk rejected a genuine aggregate")
	}
	if FastAggregateVerifyMinPk(pks, []byte("wrong message"), aggSig[:]) {
		t.Error("FastAggregateVerifyMinPk accepted the wrong message")
	}
	if FastAggregateVerifyMinPk(pks[:2], testMsg, aggSig[:]) {
		t.Error("FastAggregateVerifyMinPk accepted an aggregate missing a signer")
	}
}

func TestFastAggregateVerifyMinSig(t *testing.T) {
	privs := []*PrivateKey{privKeyN(t, 23), privKeyN(t, 24), privKeyN(t, 25)}
	pks := make([]*PublicKeyMinSig, len(privs))
	sigs := make([][]byte, len(privs))
	for i, priv := range privs {
		pks[i] = priv.PublicKeyMinSig()
		sig := signMinSig(t, priv, testMsg)
		sigs[i] = sig[:]
	}

	aggSig, err := AggregateSignaturesMinSig(sigs)
	if err != nil {
		t.Fatalf("AggregateSignaturesMinSig failed: %v", err)
	}
	if !FastAggregateVerifyMinSig(pks, testMsg, aggSig[:]) {
		t.Error("FastAggregateVerifyMinSig rejected a genuine aggregate")
	}
	if FastAggregateVerifyMinSig(pks, []byte("wrong message"), aggSig[:]) {
		t.Error("FastAggregateVerifyMinSig accepted the wrong message")
	}
}

func TestAggregateSignaturesRejectsWrongLength(t *testing.T) {
	priv := privKeyN(t, 26)
	good := signMinPk(t, priv, testMsg)
	if _, err := AggregateSignaturesMinPk([][]byte{good[:], good[:len(good)-1]}); err == nil {
		t.Error("AggregateSignaturesMinPk accepted a truncated signature")
	}
	if _, err := AggregateSignaturesMinSig([][]byte{good[:]}); err == nil {
		t.Error("AggregateSignaturesMinSig accepted a G2-length signature")
	}
}

func TestFastAggregateVerifyRejectsTamperedSignature(t *testing.T) {
	privs := []*PrivateKey{privKeyN(t, 27), privKeyN(t, 28)}
	pks := make([]*PublicKeyMinPk, len(privs))
	sigs := make([][]byte, len(privs))
	for i, priv := range privs {
		pks[i] = priv.PublicKeyMinPk()
		sig := signMinPk(t, priv, testMsg)
		sigs[i] = sig[:]
	}
	aggSig, err := AggregateSignaturesMinPk(sigs)
	if err != nil {
		t.Fatalf("AggregateSignaturesMinPk failed: %v", err)
	}

	// Flipping a bit in the x coordinate either lands off the curve (the
	// parse fails) or on a different point (the pairing check fails).
	// Either way it must not verify.
	tampered := aggSig
	tampered[len(tampered)-1] ^= 0x01
	if FastAggregateVerifyMinPk(pks, testMsg, tampered[:]) {
		t.Error("FastAggregateVerifyMinPk accepted a tampered signature")
	}
}

func TestAggregateVerifyMinPkWithDistinctMessages(t *testing.T) {
	privs := []*PrivateKey{privKeyN(t, 30), privKeyN(t, 31), privKeyN(t, 32)}
	msgs := [][]byte{[]byte("message A"), []byte("message B"), []byte("message C")}

	pks := make([]*PublicKeyMinPk, len(privs))
	sigs := make([][]byte, len(privs))
	for i, priv := range privs {
		pks[i] = priv.PublicKeyMinPk()
		sig := signMinPk(t, priv, msgs[i])
		sigs[i] = sig[:]
	}
	aggSig, err := AggregateSignaturesMinPk(sigs)
	if err != nil {
		t.Fatalf("AggregateSignaturesMinPk failed: %v", err)
	}

	if !AggregateVerifyMinPk(pks, msgs, aggSig[:]) {
		t.Error("AggregateVerifyMinPk rejected a genuine aggregate")
	}

	// Same keys, same messages, wrong pairing between them.
	swapped := [][]byte{msgs[1], msgs[0], msgs[2]}
	if AggregateVerifyMinPk(pks, swapped, aggSig[:]) {
		t.Error("AggregateVerifyMinPk accepted messages paired with the wrong keys")
	}
	if AggregateVerifyMinPk(pks, msgs[:2], aggSig[:]) {
		t.Error("AggregateVerifyMinPk accepted mismatched pks/msgs lengths")
	}
	if AggregateVerifyMinPk(nil, nil, aggSig[:]) {
		t.Error("AggregateVerifyMinPk accepted an empty set")
	}
}

func TestAggregateVerifyMinSigWithDistinctMessages(t *testing.T) {
	privs := []*PrivateKey{privKeyN(t, 33), privKeyN(t, 34)}
	msgs := [][]byte{[]byte("message A"), []byte("message B")}

	pks := make([]*PublicKeyMinSig, len(privs))
	sigs := make([][]byte, len(privs))
	for i, priv := range privs {
		pks[i] = priv.PublicKeyMinSig()
		sig := signMinSig(t, priv, msgs[i])
		sigs[i] = sig[:]
	}
	aggSig, err := AggregateSignaturesMinSig(sigs)
	if err != nil {
		t.Fatalf("AggregateSignaturesMinSig failed: %v", err)
	}

	if !AggregateVerifyMinSig(pks, msgs, aggSig[:]) {
		t.Error("AggregateVerifyMinSig rejected a genuine aggregate")
	}
	if AggregateVerifyMinSig(pks, [][]byte{msgs[1], msgs[0]}, aggSig[:]) {
		t.Error("AggregateVerifyMinSig accepted messages paired with the wrong keys")
	}
}
