package sr25519

import (
	"bytes"
	"errors"
	"testing"
)

func TestSignVRFVerifyVRFRoundTrip(t *testing.T) {
	priv := aliceKey(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	out, proof, err := SignVRF(priv, testCtx, testMsg)
	if err != nil {
		t.Fatalf("SignVRF failed: %v", err)
	}
	if !VerifyVRF(pub, testCtx, testMsg, out, proof) {
		t.Error("VerifyVRF rejected an output/proof SignVRF just produced")
	}
}

func TestSignVRFIsDeterministicOutput(t *testing.T) {
	// The VRF output itself must be deterministic (that's the point of a
	// VRF) even though the accompanying proof is randomized like an
	// ordinary schnorrkel signature.
	priv := aliceKey(t)
	out1, _, err := SignVRF(priv, testCtx, testMsg)
	if err != nil {
		t.Fatalf("SignVRF failed: %v", err)
	}
	out2, _, err := SignVRF(priv, testCtx, testMsg)
	if err != nil {
		t.Fatalf("SignVRF failed: %v", err)
	}
	if out1.Bytes() != out2.Bytes() {
		t.Error("SignVRF produced two different outputs for the same key, context, and message")
	}
}

func TestVerifyVRFRejectsWrongMessageKeyAndContext(t *testing.T) {
	priv := aliceKey(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	otherPriv := seckeyN(t, 2)
	otherPub, err := otherPriv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	out, proof, err := SignVRF(priv, testCtx, testMsg)
	if err != nil {
		t.Fatalf("SignVRF failed: %v", err)
	}

	if VerifyVRF(pub, testCtx, append(append([]byte{}, testMsg...), 0x00), out, proof) {
		t.Error("VerifyVRF accepted an output/proof under a modified message")
	}
	if VerifyVRF(otherPub, testCtx, testMsg, out, proof) {
		t.Error("VerifyVRF accepted an output/proof under the wrong public key")
	}
	if VerifyVRF(pub, []byte("different context"), testMsg, out, proof) {
		t.Error("VerifyVRF accepted an output/proof under the wrong context")
	}
}

func TestVRFOutputFromBytesRoundTrip(t *testing.T) {
	priv := aliceKey(t)
	out, _, err := SignVRF(priv, testCtx, testMsg)
	if err != nil {
		t.Fatalf("SignVRF failed: %v", err)
	}

	wire := out.Bytes()
	parsed, err := VRFOutputFromBytes(wire[:])
	if err != nil {
		t.Fatalf("VRFOutputFromBytes failed: %v", err)
	}
	if parsed.Bytes() != wire {
		t.Error("VRFOutputFromBytes(out.Bytes()) does not round trip")
	}
}

func TestVRFOutputFromBytesRejectsInvalid(t *testing.T) {
	cases := map[string][]byte{
		"empty": nil,
		"short": make([]byte, 31),
		"long":  make([]byte, 33),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := VRFOutputFromBytes(b); !errors.Is(err, ErrInvalidVRFOutput) {
				t.Errorf("VRFOutputFromBytes(%s) error = %v, want %v", name, err, ErrInvalidVRFOutput)
			}
		})
	}
}

func TestVRFProofFromBytesRoundTrip(t *testing.T) {
	priv := aliceKey(t)
	_, proof, err := SignVRF(priv, testCtx, testMsg)
	if err != nil {
		t.Fatalf("SignVRF failed: %v", err)
	}

	wire := proof.Bytes()
	parsed, err := VRFProofFromBytes(wire[:])
	if err != nil {
		t.Fatalf("VRFProofFromBytes failed: %v", err)
	}
	if parsed.Bytes() != wire {
		t.Error("VRFProofFromBytes(proof.Bytes()) does not round trip")
	}
}

func TestVRFProofFromBytesRejectsInvalid(t *testing.T) {
	cases := map[string][]byte{
		"empty": nil,
		"short": make([]byte, 63),
		"long":  make([]byte, 65),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := VRFProofFromBytes(b); !errors.Is(err, ErrInvalidVRFProof) {
				t.Errorf("VRFProofFromBytes(%s) error = %v, want %v", name, err, ErrInvalidVRFProof)
			}
		})
	}
}

func TestVRFOutputDiffersForDifferentMessages(t *testing.T) {
	priv := aliceKey(t)
	out1, _, err := SignVRF(priv, testCtx, testMsg)
	if err != nil {
		t.Fatalf("SignVRF failed: %v", err)
	}
	out2, _, err := SignVRF(priv, testCtx, []byte("a different message"))
	if err != nil {
		t.Fatalf("SignVRF failed: %v", err)
	}

	w1, w2 := out1.Bytes(), out2.Bytes()
	if bytes.Equal(w1[:], w2[:]) {
		t.Error("SignVRF produced the same output for two different messages")
	}
}
