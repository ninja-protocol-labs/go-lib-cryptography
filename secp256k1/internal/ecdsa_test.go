package internal

import (
	"encoding/hex"
	"testing"
)

func msg32(t *testing.T, s string) *[MessageLen]byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in test case: %v", err)
	}
	if len(b) != MessageLen {
		t.Fatalf("test case is %d bytes, want %d", len(b), MessageLen)
	}

	var m [MessageLen]byte
	copy(m[:], b)
	return &m
}

const testMsg = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestECDSASignVerifyRoundTrip(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)

	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	sig, ok := ECDSASignCompact(m, key)
	if !ok {
		t.Fatal("ECDSASignCompact failed for valid inputs")
	}

	if !ECDSAVerifyCompact(m, pub[:], &sig, false) {
		t.Error("ECDSAVerifyCompact rejected a signature it just produced")
	}
}

func TestECDSASignCompactIsDeterministic(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)

	sig1, ok := ECDSASignCompact(m, key)
	if !ok {
		t.Fatal("ECDSASignCompact failed for valid inputs")
	}
	sig2, ok := ECDSASignCompact(m, key)
	if !ok {
		t.Fatal("ECDSASignCompact failed for valid inputs")
	}

	if sig1 != sig2 {
		t.Error("ECDSASignCompact produced different signatures for the same msg/seckey pair")
	}
}

func TestECDSASignCompactHedgedVaries(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)

	var aux1, aux2 [32]byte
	aux1[0] = 0x01
	aux2[0] = 0x02

	sig1, ok := ECDSASignCompactHedged(m, key, &aux1)
	if !ok {
		t.Fatal("ECDSASignCompactHedged failed for valid inputs")
	}
	sig2, ok := ECDSASignCompactHedged(m, key, &aux2)
	if !ok {
		t.Fatal("ECDSASignCompactHedged failed for valid inputs")
	}

	if sig1 == sig2 {
		t.Error("ECDSASignCompactHedged produced identical signatures for different aux_rand")
	}

	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}
	if !ECDSAVerifyCompact(m, pub[:], &sig1, false) {
		t.Error("ECDSAVerifyCompact rejected a hedged signature it should accept")
	}
	if !ECDSAVerifyCompact(m, pub[:], &sig2, false) {
		t.Error("ECDSAVerifyCompact rejected a hedged signature it should accept")
	}
}

func TestECDSAVerifyCompactRejectsWrongKey(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	otherKey := seckey(t, "0000000000000000000000000000000000000000000000000000000000000002")
	m := msg32(t, testMsg)

	sig, ok := ECDSASignCompact(m, key)
	if !ok {
		t.Fatal("ECDSASignCompact failed for valid inputs")
	}

	otherPub, ok := PubkeyCreateCompressed(otherKey)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	if ECDSAVerifyCompact(m, otherPub[:], &sig, false) {
		t.Error("ECDSAVerifyCompact accepted a signature under the wrong public key")
	}
}

func TestECDSAVerifyCompactRejectsWrongMessage(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)
	otherMsg := msg32(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	sig, ok := ECDSASignCompact(m, key)
	if !ok {
		t.Fatal("ECDSASignCompact failed for valid inputs")
	}

	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	if ECDSAVerifyCompact(otherMsg, pub[:], &sig, false) {
		t.Error("ECDSAVerifyCompact accepted a signature over the wrong message")
	}
}

func TestECDSASignVerifyDERRoundTrip(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)

	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	sig, n, ok := ECDSASignDER(m, key)
	if !ok {
		t.Fatal("ECDSASignDER failed for valid inputs")
	}

	if !ECDSAVerifyDER(m, pub[:], sig[:n], false) {
		t.Error("ECDSAVerifyDER rejected a signature it just produced")
	}
}

func TestECDSASignDERHedgedVaries(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)

	var aux1, aux2 [32]byte
	aux1[0] = 0x01
	aux2[0] = 0x02

	sig1, n1, ok := ECDSASignDERHedged(m, key, &aux1)
	if !ok {
		t.Fatal("ECDSASignDERHedged failed for valid inputs")
	}
	sig2, n2, ok := ECDSASignDERHedged(m, key, &aux2)
	if !ok {
		t.Fatal("ECDSASignDERHedged failed for valid inputs")
	}

	if n1 == n2 && sig1 == sig2 {
		t.Error("ECDSASignDERHedged produced identical signatures for different aux_rand")
	}
}

func TestECDSAVerifyDERRejectsWrongKey(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	otherKey := seckey(t, "0000000000000000000000000000000000000000000000000000000000000002")
	m := msg32(t, testMsg)

	sig, n, ok := ECDSASignDER(m, key)
	if !ok {
		t.Fatal("ECDSASignDER failed for valid inputs")
	}

	otherPub, ok := PubkeyCreateCompressed(otherKey)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	if ECDSAVerifyDER(m, otherPub[:], sig[:n], false) {
		t.Error("ECDSAVerifyDER accepted a signature under the wrong public key")
	}
}

func TestECDSASignatureCompactDERConversion(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)

	compact, ok := ECDSASignCompact(m, key)
	if !ok {
		t.Fatal("ECDSASignCompact failed for valid inputs")
	}

	der, n, ok := ECDSASignatureCompactToDER(&compact)
	if !ok {
		t.Fatal("ECDSASignatureCompactToDER failed for a valid signature")
	}

	backToCompact, ok := ECDSASignatureDERToCompact(der[:n])
	if !ok {
		t.Fatal("ECDSASignatureDERToCompact failed for a valid signature")
	}

	if backToCompact != compact {
		t.Error("compact -> DER -> compact round trip did not reproduce the original signature")
	}
}

func TestECDSASignatureDERToCompactRejectsInvalid(t *testing.T) {
	if _, ok := ECDSASignatureDERToCompact(nil); ok {
		t.Error("ECDSASignatureDERToCompact succeeded for empty input")
	}
	if _, ok := ECDSASignatureDERToCompact([]byte{0x30, 0x00}); ok {
		t.Error("ECDSASignatureDERToCompact succeeded for a malformed DER signature")
	}
}

func TestECDSASignatureNormalize(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)

	sig, ok := ECDSASignCompact(m, key)
	if !ok {
		t.Fatal("ECDSASignCompact failed for valid inputs")
	}

	// secp256k1_ecdsa_sign always returns low-S, so normalizing an already
	// normalized signature must be a no-op and report wasHigh == false.
	normalized, wasHigh, ok := ECDSASignatureNormalize(&sig)
	if !ok {
		t.Fatal("ECDSASignatureNormalize failed for a valid signature")
	}
	if wasHigh {
		t.Error("ECDSASignatureNormalize reported a low-S signature as high-S")
	}
	if normalized != sig {
		t.Error("ECDSASignatureNormalize changed an already-normalized signature")
	}
}

func TestECDSASignVerifyDERDoesNotAllocate(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)
	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	if got := testing.AllocsPerRun(100, func() { ECDSASignDER(m, key) }); got != 0 {
		t.Errorf("ECDSASignDER allocated %v times per run, want 0", got)
	}

	sig, n, _ := ECDSASignDER(m, key)
	if got := testing.AllocsPerRun(100, func() { ECDSAVerifyDER(m, pub[:], sig[:n], false) }); got != 0 {
		t.Errorf("ECDSAVerifyDER allocated %v times per run, want 0", got)
	}
}

func TestECDSASignVerifyDoesNotAllocate(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)
	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	if got := testing.AllocsPerRun(100, func() { ECDSASignCompact(m, key) }); got != 0 {
		t.Errorf("ECDSASignCompact allocated %v times per run, want 0", got)
	}

	sig, _ := ECDSASignCompact(m, key)
	if got := testing.AllocsPerRun(100, func() { ECDSAVerifyCompact(m, pub[:], &sig, false) }); got != 0 {
		t.Errorf("ECDSAVerifyCompact allocated %v times per run, want 0", got)
	}
}

func TestECDSASignRecoverableRoundTrip(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)

	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	sig, recID, ok := ECDSASignRecoverable(m, key)
	if !ok {
		t.Fatal("ECDSASignRecoverable failed for valid inputs")
	}

	recovered, ok := ECDSARecoverCompressed(m, &sig, recID)
	if !ok {
		t.Fatal("ECDSARecoverCompressed failed for a valid signature")
	}
	if recovered != pub {
		t.Error("ECDSARecoverCompressed did not recover the signer's public key")
	}

	// The recoverable signature's 64 bytes must equal what ECDSASignCompact
	// produces for the same input: recovery only adds a 2-bit index on top of
	// an otherwise ordinary signature.
	compactSig, ok := ECDSASignCompact(m, key)
	if !ok {
		t.Fatal("ECDSASignCompact failed for valid inputs")
	}
	if sig != compactSig {
		t.Error("ECDSASignRecoverable's 64-byte signature differs from ECDSASignCompact's")
	}
}

func TestECDSARecoverRejectsWrongRecoveryID(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)

	pub, ok := PubkeyCreateCompressed(key)
	if !ok {
		t.Fatal("PubkeyCreateCompressed failed for a valid key")
	}

	sig, recID, ok := ECDSASignRecoverable(m, key)
	if !ok {
		t.Fatal("ECDSASignRecoverable failed for valid inputs")
	}

	wrongID := (recID + 1) % 4
	if recovered, ok := ECDSARecoverCompressed(m, &sig, wrongID); ok && recovered == pub {
		t.Error("ECDSARecoverCompressed recovered the correct key from the wrong recovery id")
	}
}

// recoveryID is a plain int, so nothing stops a caller from passing a value
// outside libsecp256k1's only valid range, [0, 3]. Upstream itself rejects
// it, but only via its illegal-argument path, which is why this is guarded
// before ever crossing into C rather than left to that fallback.
func TestECDSARecoverRejectsOutOfRangeRecoveryID(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)
	sig, _, ok := ECDSASignRecoverable(m, key)
	if !ok {
		t.Fatal("ECDSASignRecoverable failed for valid inputs")
	}

	for _, badID := range []int{-1, 4, 99} {
		if _, ok := ECDSARecoverCompressed(m, &sig, badID); ok {
			t.Errorf("ECDSARecoverCompressed succeeded with out-of-range recoveryID=%d", badID)
		}
		if _, ok := ECDSARecoverUncompressed(m, &sig, badID); ok {
			t.Errorf("ECDSARecoverUncompressed succeeded with out-of-range recoveryID=%d", badID)
		}
	}
}

func TestECDSASignRecoverableHedgedVaries(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)

	var aux1, aux2 [32]byte
	aux1[0] = 0x01
	aux2[0] = 0x02

	sig1, _, ok := ECDSASignRecoverableHedged(m, key, &aux1)
	if !ok {
		t.Fatal("ECDSASignRecoverableHedged failed for valid inputs")
	}
	sig2, _, ok := ECDSASignRecoverableHedged(m, key, &aux2)
	if !ok {
		t.Fatal("ECDSASignRecoverableHedged failed for valid inputs")
	}

	if sig1 == sig2 {
		t.Error("ECDSASignRecoverableHedged produced identical signatures for different aux_rand")
	}
}

func TestECDSARecoverableDoesNotAllocate(t *testing.T) {
	key := seckey(t, "0000000000000000000000000000000000000000000000000000000000000001")
	m := msg32(t, testMsg)

	if got := testing.AllocsPerRun(100, func() { ECDSASignRecoverable(m, key) }); got != 0 {
		t.Errorf("ECDSASignRecoverable allocated %v times per run, want 0", got)
	}

	sig, recID, _ := ECDSASignRecoverable(m, key)
	if got := testing.AllocsPerRun(100, func() { ECDSARecoverCompressed(m, &sig, recID) }); got != 0 {
		t.Errorf("ECDSARecoverCompressed allocated %v times per run, want 0", got)
	}
}
