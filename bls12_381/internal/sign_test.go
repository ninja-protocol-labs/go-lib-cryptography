package internal

import (
	"bytes"
	"testing"
)

func TestSignMsgPkInG1RoundTrip(t *testing.T) {
	sk := Keygen(bytes.Repeat([]byte{0x11}, 32), nil)
	pkCompressed := SkToPkInG1Compressed(&sk)
	pk, code := P1Uncompress(&pkCompressed)
	if code != ErrSuccess {
		t.Fatalf("P1Uncompress failed: code %d", code)
	}

	sigCompressed := SignMsgPkInG1(&sk, testMsg, testDst, nil)
	sig, code := P2Uncompress(&sigCompressed)
	if code != ErrSuccess {
		t.Fatalf("P2Uncompress failed: code %d", code)
	}

	if code := CoreVerifyPkInG1(&pk, &sig, true, testMsg, testDst, nil); code != ErrSuccess {
		t.Errorf("CoreVerifyPkInG1 rejected a genuine signature: code %d", code)
	}
	if code := CoreVerifyPkInG1(&pk, &sig, true, []byte("a different message"), testDst, nil); code == ErrSuccess {
		t.Error("CoreVerifyPkInG1 accepted a signature over the wrong message")
	}
}

func TestSignPkInG1MatchesSignMsgPkInG1(t *testing.T) {
	// Signing a pre-hashed point must agree with the one-shot hash-then-sign
	// path — the same algebraic property the point.go tests check for
	// arithmetic, applied here to signing.
	sk := Keygen(bytes.Repeat([]byte{0x12}, 32), nil)

	hash := HashToG2(testMsg, testDst, nil)
	sig := SignPkInG1(&hash, &sk)
	sigCompressed := P2AffineCompress(&sig)

	oneShot := SignMsgPkInG1(&sk, testMsg, testDst, nil)
	if sigCompressed != oneShot {
		t.Error("SignPkInG1(HashToG2(msg)) != SignMsgPkInG1(msg)")
	}
}

func TestSignMsgPkInG2RoundTrip(t *testing.T) {
	sk := Keygen(bytes.Repeat([]byte{0x13}, 32), nil)
	pkCompressed := SkToPkInG2Compressed(&sk)
	pk, code := P2Uncompress(&pkCompressed)
	if code != ErrSuccess {
		t.Fatalf("P2Uncompress failed: code %d", code)
	}

	sigCompressed := SignMsgPkInG2(&sk, testMsg, testDst, nil)
	sig, code := P1Uncompress(&sigCompressed)
	if code != ErrSuccess {
		t.Fatalf("P1Uncompress failed: code %d", code)
	}

	if code := CoreVerifyPkInG2(&pk, &sig, true, testMsg, testDst, nil); code != ErrSuccess {
		t.Errorf("CoreVerifyPkInG2 rejected a genuine signature: code %d", code)
	}
	if code := CoreVerifyPkInG2(&pk, &sig, true, []byte("a different message"), testDst, nil); code == ErrSuccess {
		t.Error("CoreVerifyPkInG2 accepted a signature over the wrong message")
	}
}

func TestSignPkInG2MatchesSignMsgPkInG2(t *testing.T) {
	sk := Keygen(bytes.Repeat([]byte{0x14}, 32), nil)

	hash := HashToG1(testMsg, testDst, nil)
	sig := SignPkInG2(&hash, &sk)
	sigCompressed := P1AffineCompress(&sig)

	oneShot := SignMsgPkInG2(&sk, testMsg, testDst, nil)
	if sigCompressed != oneShot {
		t.Error("SignPkInG2(HashToG1(msg)) != SignMsgPkInG2(msg)")
	}
}

func TestCoreVerifyRejectsWrongKey(t *testing.T) {
	skA := Keygen(bytes.Repeat([]byte{0x15}, 32), nil)
	skB := Keygen(bytes.Repeat([]byte{0x16}, 32), nil)

	pkBCompressed := SkToPkInG1Compressed(&skB)
	pkB, _ := P1Uncompress(&pkBCompressed)

	sigCompressed := SignMsgPkInG1(&skA, testMsg, testDst, nil)
	sig, _ := P2Uncompress(&sigCompressed)

	if code := CoreVerifyPkInG1(&pkB, &sig, true, testMsg, testDst, nil); code == ErrSuccess {
		t.Error("CoreVerifyPkInG1 accepted a signature under the wrong public key")
	}
}

func TestSignAndVerifyFuncsAllocs(t *testing.T) {
	sk := Keygen(bytes.Repeat([]byte{0x17}, 32), nil)
	pkCompressed := SkToPkInG1Compressed(&sk)
	pk, _ := P1Uncompress(&pkCompressed)
	hash := HashToG2(testMsg, testDst, nil)
	sig := SignPkInG1(&hash, &sk)

	allocs := testing.AllocsPerRun(1000, func() {
		SignPkInG1(&hash, &sk)
		SignMsgPkInG1(&sk, testMsg, testDst, nil)
		CoreVerifyPkInG1(&pk, &sig, true, testMsg, testDst, nil)
	})
	if allocs != 0 {
		t.Errorf("sign/verify functions allocated %v times per run, want 0", allocs)
	}
}
