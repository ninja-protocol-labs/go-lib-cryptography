package bn254

import (
	"bytes"
	"testing"
)

func TestSignVerifyMinPkRoundTrip(t *testing.T) {
	priv := privKeyN(t, 10)
	sig := signMinPk(t, priv, testMsg)
	if !VerifyMinPk(priv.PublicKeyMinPk(), testMsg, sig[:]) {
		t.Error("VerifyMinPk rejected a genuine signature")
	}
}

func TestSignVerifyMinSigRoundTrip(t *testing.T) {
	priv := privKeyN(t, 10)
	sig := signMinSig(t, priv, testMsg)
	if !VerifyMinSig(priv.PublicKeyMinSig(), testMsg, sig[:]) {
		t.Error("VerifyMinSig rejected a genuine signature")
	}
}

func TestSignIsDeterministic(t *testing.T) {
	priv := privKeyN(t, 11)
	if signMinPk(t, priv, testMsg) != signMinPk(t, priv, testMsg) {
		t.Error("SignMinPk is not deterministic")
	}
	if signMinSig(t, priv, testMsg) != signMinSig(t, priv, testMsg) {
		t.Error("SignMinSig is not deterministic")
	}
}

func TestVerifyMinPkRejectsWrongInputs(t *testing.T) {
	priv := privKeyN(t, 12)
	pub := priv.PublicKeyMinPk()
	sig := signMinPk(t, priv, testMsg)

	if VerifyMinPk(pub, []byte("a different message"), sig[:]) {
		t.Error("VerifyMinPk accepted a signature over the wrong message")
	}
	if VerifyMinPk(privKeyN(t, 13).PublicKeyMinPk(), testMsg, sig[:]) {
		t.Error("VerifyMinPk accepted a signature under the wrong key")
	}
	if VerifyMinPk(nil, testMsg, sig[:]) {
		t.Error("VerifyMinPk accepted a nil public key")
	}
	if VerifyMinPk(pub, testMsg, sig[:len(sig)-1]) {
		t.Error("VerifyMinPk accepted a truncated signature")
	}
	if VerifyMinPk(pub, testMsg, make([]byte, SignatureMinPkLen)) {
		t.Error("VerifyMinPk accepted an all-zero signature")
	}
}

func TestVerifyMinSigRejectsWrongInputs(t *testing.T) {
	priv := privKeyN(t, 12)
	pub := priv.PublicKeyMinSig()
	sig := signMinSig(t, priv, testMsg)

	if VerifyMinSig(pub, []byte("a different message"), sig[:]) {
		t.Error("VerifyMinSig accepted a signature over the wrong message")
	}
	if VerifyMinSig(privKeyN(t, 13).PublicKeyMinSig(), testMsg, sig[:]) {
		t.Error("VerifyMinSig accepted a signature under the wrong key")
	}
	if VerifyMinSig(nil, testMsg, sig[:]) {
		t.Error("VerifyMinSig accepted a nil public key")
	}
	if VerifyMinSig(pub, testMsg, make([]byte, SignatureMinSigLen)) {
		t.Error("VerifyMinSig accepted an all-zero signature")
	}
}

func TestTheTwoSchemesDoNotInteroperate(t *testing.T) {
	// A min-pk signature is a G2 point and a min-sig signature is a G1
	// point, so they are not even the same length — the schemes cannot be
	// confused for one another at the wire level, let alone verify across.
	if SignatureMinPkLen == SignatureMinSigLen {
		t.Error("min-pk and min-sig signatures have the same length")
	}
}

func TestSignWithDSTChangesTheSignature(t *testing.T) {
	priv := privKeyN(t, 15)
	custom := []byte("SOME_APPLICATION_SPECIFIC_DST_")

	sig, err := SignMinPkWithDST(priv, testMsg, custom)
	if err != nil {
		t.Fatalf("SignMinPkWithDST failed: %v", err)
	}
	if sig == signMinPk(t, priv, testMsg) {
		t.Error("a custom DST produced the same signature as the default one")
	}
	if !VerifyMinPkWithDST(priv.PublicKeyMinPk(), testMsg, sig[:], custom) {
		t.Error("VerifyMinPkWithDST rejected a signature made under the same DST")
	}
	if VerifyMinPk(priv.PublicKeyMinPk(), testMsg, sig[:]) {
		t.Error("the default DST verified a signature made under a custom one")
	}

	sigMinSig, err := SignMinSigWithDST(priv, testMsg, custom)
	if err != nil {
		t.Fatalf("SignMinSigWithDST failed: %v", err)
	}
	if !VerifyMinSigWithDST(priv.PublicKeyMinSig(), testMsg, sigMinSig[:], custom) {
		t.Error("VerifyMinSigWithDST rejected a signature made under the same DST")
	}
	if VerifyMinSig(priv.PublicKeyMinSig(), testMsg, sigMinSig[:]) {
		t.Error("the default DST verified a min-sig signature made under a custom one")
	}
}

func TestSignRejectsOverlongDST(t *testing.T) {
	// expand_message_xmd encodes the DST length in a single byte, so
	// anything past 255 bytes cannot be represented.
	priv := privKeyN(t, 16)
	dst := bytes.Repeat([]byte{'x'}, 256)
	if _, err := SignMinPkWithDST(priv, testMsg, dst); err == nil {
		t.Error("SignMinPkWithDST accepted a 256-byte DST")
	}
	if _, err := SignMinSigWithDST(priv, testMsg, dst); err == nil {
		t.Error("SignMinSigWithDST accepted a 256-byte DST")
	}
}

func TestSignRejectsNilKey(t *testing.T) {
	if _, err := SignMinPk(nil, testMsg); err == nil {
		t.Error("SignMinPk accepted a nil private key")
	}
	if _, err := SignMinSig(nil, testMsg); err == nil {
		t.Error("SignMinSig accepted a nil private key")
	}
}
