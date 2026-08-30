package secp256k1

import (
	"testing"

	"github.com/ninja-protocol-labs/go-lib-cryptography/secp256k1/internal"
)

var testMsg = []byte("the quick brown fox jumps over the lazy dog")

func TestSignCompactVerifyCompactRoundTrip(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	sig, err := SignCompact(priv, testMsg)
	if err != nil {
		t.Fatalf("SignCompact failed: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("SignCompact produced %d bytes, want 64", len(sig))
	}

	if !VerifyCompact(pub, testMsg, sig, false) {
		t.Error("VerifyCompact rejected a signature it just produced")
	}
}

func TestSignDERVerifyDERRoundTrip(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	sig, err := SignDER(priv, testMsg)
	if err != nil {
		t.Fatalf("SignDER failed: %v", err)
	}

	if !VerifyDER(pub, testMsg, sig, false) {
		t.Error("VerifyDER rejected a signature it just produced")
	}
}

func TestSignCompactIsDeterministic(t *testing.T) {
	priv := seckeyOne(t)

	sig1, err := SignCompact(priv, testMsg)
	if err != nil {
		t.Fatalf("SignCompact failed: %v", err)
	}
	sig2, err := SignCompact(priv, testMsg)
	if err != nil {
		t.Fatalf("SignCompact failed: %v", err)
	}

	if string(sig1) != string(sig2) {
		t.Error("SignCompact produced different signatures for the same key/message")
	}
}

func TestSignCompactHedgedVaries(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	var aux1, aux2 [32]byte
	aux1[0] = 0x01
	aux2[0] = 0x02

	sig1, err := SignCompactHedged(priv, testMsg, &aux1)
	if err != nil {
		t.Fatalf("SignCompactHedged failed: %v", err)
	}
	sig2, err := SignCompactHedged(priv, testMsg, &aux2)
	if err != nil {
		t.Fatalf("SignCompactHedged failed: %v", err)
	}

	if string(sig1) == string(sig2) {
		t.Error("SignCompactHedged produced identical signatures for different aux_rand")
	}
	if !VerifyCompact(pub, testMsg, sig1, false) || !VerifyCompact(pub, testMsg, sig2, false) {
		t.Error("VerifyCompact rejected a hedged signature it should accept")
	}
}

func TestVerifyCompactRejectsWrongKeyAndMessage(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	otherPriv, err := PrivateKeyFromBytes(append(make([]byte, 31), 2))
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed: %v", err)
	}
	otherPub, err := otherPriv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	sig, err := SignCompact(priv, testMsg)
	if err != nil {
		t.Fatalf("SignCompact failed: %v", err)
	}

	if VerifyCompact(otherPub, testMsg, sig, false) {
		t.Error("VerifyCompact accepted a signature under the wrong public key")
	}
	if VerifyCompact(pub, []byte("a different message"), sig, false) {
		t.Error("VerifyCompact accepted a signature over the wrong message")
	}
}

func TestSignAndRecoverRoundTrip(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	sig, recID, err := SignRecoverable(priv, testMsg)
	if err != nil {
		t.Fatalf("SignRecoverable failed: %v", err)
	}

	recovered, err := Recover(testMsg, sig, recID)
	if err != nil {
		t.Fatalf("Recover failed: %v", err)
	}
	if !recovered.Equal(pub) {
		t.Error("Recover did not reconstruct the signer's public key")
	}
}

func TestRecoverRejectsWrongRecoveryID(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	sig, recID, err := SignRecoverable(priv, testMsg)
	if err != nil {
		t.Fatalf("SignRecoverable failed: %v", err)
	}

	wrongID := (recID + 1) % 4
	if recovered, err := Recover(testMsg, sig, wrongID); err == nil && recovered.Equal(pub) {
		t.Error("Recover reconstructed the correct key from the wrong recovery id")
	}
}

func TestRecoverRejectsInvalidSignature(t *testing.T) {
	if _, err := Recover(testMsg, []byte{0x01, 0x02}, 0); err != ErrInvalidSignature {
		t.Errorf("Recover error = %v, want %v", err, ErrInvalidSignature)
	}
}

func TestSignDigestCompactRoundTrip(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	var digest [32]byte
	copy(digest[:], testMsg)

	sig, err := SignDigestCompact(priv, digest)
	if err != nil {
		t.Fatalf("SignDigestCompact failed: %v", err)
	}
	if !VerifyDigestCompact(pub, digest, sig, false) {
		t.Error("VerifyDigestCompact rejected a signature it just produced")
	}
}

func TestSignDigestCompactHedgedVaries(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	var digest [32]byte
	copy(digest[:], testMsg)

	var aux1, aux2 [32]byte
	aux1[0] = 0x01
	aux2[0] = 0x02

	sig1, err := SignDigestCompactHedged(priv, digest, &aux1)
	if err != nil {
		t.Fatalf("SignDigestCompactHedged failed: %v", err)
	}
	sig2, err := SignDigestCompactHedged(priv, digest, &aux2)
	if err != nil {
		t.Fatalf("SignDigestCompactHedged failed: %v", err)
	}

	if string(sig1) == string(sig2) {
		t.Error("SignDigestCompactHedged produced identical signatures for different aux_rand")
	}
	if !VerifyDigestCompact(pub, digest, sig1, false) || !VerifyDigestCompact(pub, digest, sig2, false) {
		t.Error("VerifyDigestCompact rejected a hedged signature it should accept")
	}
}

func TestSignDigestDERRoundTrip(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	var digest [32]byte
	copy(digest[:], testMsg)

	sig, err := SignDigestDER(priv, digest)
	if err != nil {
		t.Fatalf("SignDigestDER failed: %v", err)
	}
	if !VerifyDigestDER(pub, digest, sig, false) {
		t.Error("VerifyDigestDER rejected a signature it just produced")
	}
}

func TestSignDERHedgedVaries(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	var aux1, aux2 [32]byte
	aux1[0] = 0x01
	aux2[0] = 0x02

	sig1, err := SignDERHedged(priv, testMsg, &aux1)
	if err != nil {
		t.Fatalf("SignDERHedged failed: %v", err)
	}
	sig2, err := SignDERHedged(priv, testMsg, &aux2)
	if err != nil {
		t.Fatalf("SignDERHedged failed: %v", err)
	}

	if string(sig1) == string(sig2) {
		t.Error("SignDERHedged produced identical signatures for different aux_rand")
	}
	if !VerifyDER(pub, testMsg, sig1, false) || !VerifyDER(pub, testMsg, sig2, false) {
		t.Error("VerifyDER rejected a hedged signature it should accept")
	}
}

func TestSignDigestDERHedgedVaries(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	var digest [32]byte
	copy(digest[:], testMsg)

	var aux1, aux2 [32]byte
	aux1[0] = 0x01
	aux2[0] = 0x02

	sig1, err := SignDigestDERHedged(priv, digest, &aux1)
	if err != nil {
		t.Fatalf("SignDigestDERHedged failed: %v", err)
	}
	sig2, err := SignDigestDERHedged(priv, digest, &aux2)
	if err != nil {
		t.Fatalf("SignDigestDERHedged failed: %v", err)
	}

	if string(sig1) == string(sig2) {
		t.Error("SignDigestDERHedged produced identical signatures for different aux_rand")
	}
	if !VerifyDigestDER(pub, digest, sig1, false) || !VerifyDigestDER(pub, digest, sig2, false) {
		t.Error("VerifyDigestDER rejected a hedged signature it should accept")
	}
}

func TestSignDigestRecoverableRoundTrip(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	var digest [32]byte
	copy(digest[:], testMsg)

	sig, recID, err := SignDigestRecoverable(priv, digest)
	if err != nil {
		t.Fatalf("SignDigestRecoverable failed: %v", err)
	}

	recovered, err := RecoverDigest(digest, sig, recID)
	if err != nil {
		t.Fatalf("RecoverDigest failed: %v", err)
	}
	if !recovered.Equal(pub) {
		t.Error("RecoverDigest did not reconstruct the signer's public key")
	}
}

func TestSignRecoverableHedgedVaries(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	var aux1, aux2 [32]byte
	aux1[0] = 0x01
	aux2[0] = 0x02

	sig1, recID1, err := SignRecoverableHedged(priv, testMsg, &aux1)
	if err != nil {
		t.Fatalf("SignRecoverableHedged failed: %v", err)
	}
	sig2, recID2, err := SignRecoverableHedged(priv, testMsg, &aux2)
	if err != nil {
		t.Fatalf("SignRecoverableHedged failed: %v", err)
	}

	if string(sig1) == string(sig2) {
		t.Error("SignRecoverableHedged produced identical signatures for different aux_rand")
	}
	recovered1, err := Recover(testMsg, sig1, recID1)
	if err != nil {
		t.Fatalf("Recover failed: %v", err)
	}
	recovered2, err := Recover(testMsg, sig2, recID2)
	if err != nil {
		t.Fatalf("Recover failed: %v", err)
	}
	if !recovered1.Equal(pub) || !recovered2.Equal(pub) {
		t.Error("Recover did not reconstruct the signer's public key from a hedged recoverable signature")
	}
}

func TestSignDigestRecoverableHedgedVaries(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	var digest [32]byte
	copy(digest[:], testMsg)

	var aux1, aux2 [32]byte
	aux1[0] = 0x01
	aux2[0] = 0x02

	sig1, recID1, err := SignDigestRecoverableHedged(priv, digest, &aux1)
	if err != nil {
		t.Fatalf("SignDigestRecoverableHedged failed: %v", err)
	}
	sig2, recID2, err := SignDigestRecoverableHedged(priv, digest, &aux2)
	if err != nil {
		t.Fatalf("SignDigestRecoverableHedged failed: %v", err)
	}

	if string(sig1) == string(sig2) {
		t.Error("SignDigestRecoverableHedged produced identical signatures for different aux_rand")
	}
	recovered1, err := RecoverDigest(digest, sig1, recID1)
	if err != nil {
		t.Fatalf("RecoverDigest failed: %v", err)
	}
	recovered2, err := RecoverDigest(digest, sig2, recID2)
	if err != nil {
		t.Fatalf("RecoverDigest failed: %v", err)
	}
	if !recovered1.Equal(pub) || !recovered2.Equal(pub) {
		t.Error("RecoverDigest did not reconstruct the signer's public key from a hedged recoverable signature")
	}
}

func TestVerifyCompactAllowHighS(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	sig, err := SignCompact(priv, testMsg)
	if err != nil {
		t.Fatalf("SignCompact failed: %v", err)
	}
	highS := flipHighS(t, sig)

	if VerifyCompact(pub, testMsg, highS, false) {
		t.Error("VerifyCompact accepted a high-S signature with allowHighS=false")
	}
	if !VerifyCompact(pub, testMsg, highS, true) {
		t.Error("VerifyCompact rejected a high-S signature with allowHighS=true")
	}
}

func TestVerifyDERAllowHighS(t *testing.T) {
	priv := seckeyOne(t)
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	sig, err := SignCompact(priv, testMsg)
	if err != nil {
		t.Fatalf("SignCompact failed: %v", err)
	}
	highSCompact := flipHighS(t, sig)

	var fixed [internal.SignatureCompactLen]byte
	copy(fixed[:], highSCompact)
	derArr, n, ok := internal.ECDSASignatureCompactToDER(&fixed)
	if !ok {
		t.Fatal("ECDSASignatureCompactToDER failed for a valid compact signature")
	}
	highSDER := derArr[:n]

	if VerifyDER(pub, testMsg, highSDER, false) {
		t.Error("VerifyDER accepted a high-S signature with allowHighS=false")
	}
	if !VerifyDER(pub, testMsg, highSDER, true) {
		t.Error("VerifyDER rejected a high-S signature with allowHighS=true")
	}
}

func TestRecoverDigestRejectsInvalidSignature(t *testing.T) {
	var digest [32]byte
	copy(digest[:], testMsg)
	if _, err := RecoverDigest(digest, []byte{0x01, 0x02}, 0); err != ErrInvalidSignature {
		t.Errorf("RecoverDigest error = %v, want %v", err, ErrInvalidSignature)
	}
}
