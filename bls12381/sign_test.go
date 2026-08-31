package bls12381

import (
	"testing"

	"github.com/ninja-protocol-labs/go-lib-cryptography/bls12381/internal"
)

func TestSignMinPkVerifyMinPkRoundTrip(t *testing.T) {
	priv := privKeyN(t, 9)
	pub := priv.PublicKeyMinPk()

	sig := SignMinPk(priv, testMsg)
	if len(sig) != internal.P2CompressedLen {
		t.Fatalf("SignMinPk produced %d bytes, want %d", len(sig), internal.P2CompressedLen)
	}
	if !VerifyMinPk(pub, testMsg, sig) {
		t.Error("VerifyMinPk rejected a signature it just produced")
	}
}

func TestSignMinSigVerifyMinSigRoundTrip(t *testing.T) {
	priv := privKeyN(t, 10)
	pub := priv.PublicKeyMinSig()

	sig := SignMinSig(priv, testMsg)
	if len(sig) != internal.P1CompressedLen {
		t.Fatalf("SignMinSig produced %d bytes, want %d", len(sig), internal.P1CompressedLen)
	}
	if !VerifyMinSig(pub, testMsg, sig) {
		t.Error("VerifyMinSig rejected a signature it just produced")
	}
}

func TestSignMinPkIsDeterministic(t *testing.T) {
	priv := privKeyN(t, 11)

	sig1 := SignMinPk(priv, testMsg)
	sig2 := SignMinPk(priv, testMsg)
	if string(sig1) != string(sig2) {
		t.Error("SignMinPk produced different signatures for the same key/message")
	}
}

func TestSignMinSigIsDeterministic(t *testing.T) {
	priv := privKeyN(t, 12)

	sig1 := SignMinSig(priv, testMsg)
	sig2 := SignMinSig(priv, testMsg)
	if string(sig1) != string(sig2) {
		t.Error("SignMinSig produced different signatures for the same key/message")
	}
}

func TestVerifyMinPkRejectsWrongMessage(t *testing.T) {
	priv := privKeyN(t, 13)
	pub := priv.PublicKeyMinPk()
	sig := SignMinPk(priv, testMsg)

	if VerifyMinPk(pub, []byte("a different message"), sig) {
		t.Error("VerifyMinPk accepted a signature over the wrong message")
	}
}

func TestVerifyMinSigRejectsWrongMessage(t *testing.T) {
	priv := privKeyN(t, 14)
	pub := priv.PublicKeyMinSig()
	sig := SignMinSig(priv, testMsg)

	if VerifyMinSig(pub, []byte("a different message"), sig) {
		t.Error("VerifyMinSig accepted a signature over the wrong message")
	}
}

func TestVerifyMinPkRejectsWrongKey(t *testing.T) {
	privA := privKeyN(t, 15)
	privB := privKeyN(t, 16)
	pubB := privB.PublicKeyMinPk()
	sig := SignMinPk(privA, testMsg)

	if VerifyMinPk(pubB, testMsg, sig) {
		t.Error("VerifyMinPk accepted a signature under the wrong public key")
	}
}

func TestVerifyMinSigRejectsWrongKey(t *testing.T) {
	privA := privKeyN(t, 17)
	privB := privKeyN(t, 18)
	pubB := privB.PublicKeyMinSig()
	sig := SignMinSig(privA, testMsg)

	if VerifyMinSig(pubB, testMsg, sig) {
		t.Error("VerifyMinSig accepted a signature under the wrong public key")
	}
}

func TestVerifyMinPkRejectsMalformedInput(t *testing.T) {
	priv := privKeyN(t, 19)
	pub := priv.PublicKeyMinPk()

	if VerifyMinPk(pub, testMsg, nil) {
		t.Error("VerifyMinPk accepted a nil signature")
	}
	if VerifyMinPk(nil, testMsg, SignMinPk(priv, testMsg)) {
		t.Error("VerifyMinPk accepted a nil public key")
	}
}

func TestVerifyMinSigRejectsMalformedInput(t *testing.T) {
	priv := privKeyN(t, 20)
	pub := priv.PublicKeyMinSig()

	if VerifyMinSig(pub, testMsg, nil) {
		t.Error("VerifyMinSig accepted a nil signature")
	}
	if VerifyMinSig(nil, testMsg, SignMinSig(priv, testMsg)) {
		t.Error("VerifyMinSig accepted a nil public key")
	}
}

func TestSignMinPkWithDSTChangesSignature(t *testing.T) {
	priv := privKeyN(t, 21)
	pub := priv.PublicKeyMinPk()

	defaultSig := SignMinPk(priv, testMsg)
	customDST := []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_CUSTOM_")
	customSig := SignMinPkWithDST(priv, testMsg, customDST)

	if string(defaultSig) == string(customSig) {
		t.Error("SignMinPkWithDST produced the same signature as the default DST")
	}
	if !VerifyMinPkWithDST(pub, testMsg, customSig, customDST) {
		t.Error("VerifyMinPkWithDST rejected a signature made with the matching custom DST")
	}
	if VerifyMinPk(pub, testMsg, customSig) {
		t.Error("VerifyMinPk (default DST) accepted a signature made with a different DST")
	}
}

func TestSignMinSigWithDSTChangesSignature(t *testing.T) {
	priv := privKeyN(t, 22)
	pub := priv.PublicKeyMinSig()

	defaultSig := SignMinSig(priv, testMsg)
	customDST := []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_CUSTOM_")
	customSig := SignMinSigWithDST(priv, testMsg, customDST)

	if string(defaultSig) == string(customSig) {
		t.Error("SignMinSigWithDST produced the same signature as the default DST")
	}
	if !VerifyMinSigWithDST(pub, testMsg, customSig, customDST) {
		t.Error("VerifyMinSigWithDST rejected a signature made with the matching custom DST")
	}
	if VerifyMinSig(pub, testMsg, customSig) {
		t.Error("VerifyMinSig (default DST) accepted a signature made with a different DST")
	}
}
