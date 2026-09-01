package secp256k1

import (
	"crypto/sha256"
	"errors"
	"testing"
)

// The exact 32-byte value MuSig2 sessions in this file sign for. MuSig2
// treats msg32 as an opaque 32-byte value, unlike SignSchnorr/VerifySchnorr,
// which hash an arbitrary-length message internally — so this is computed
// once and reused everywhere a MuSig2 msg is needed, including the plain
// VerifySchnorr check at the end.
var musigTestDigest = sha256.Sum256(testMsg)

func musigKey(t *testing.T, lastByte byte) (*PrivateKey, *PublicKey) {
	t.Helper()
	b := make([]byte, 32)
	b[31] = lastByte
	priv, err := PrivateKeyFromBytes(b)
	if err != nil {
		t.Fatalf("PrivateKeyFromBytes failed: %v", err)
	}
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	return priv, pub
}

// A minimal 2-signer setup through MusigProcessNonce, reused by several
// tests below.
type musigTwoSignerSession struct {
	priv1, priv2 *PrivateKey
	pub1, pub2   *PublicKey
	aggPk        *PublicKey
	cache        *MusigKeyaggCache
	secnonce1    *MusigSecnonce
	pubnonce1    *MusigPubNonce
	secnonce2    *MusigSecnonce
	pubnonce2    *MusigPubNonce
	aggNonce     *MusigAggNonce
	session      *MusigSession
}

func newMusigTwoSignerSession(t *testing.T) musigTwoSignerSession {
	t.Helper()

	priv1, pub1 := musigKey(t, 1)
	priv2, pub2 := musigKey(t, 2)

	aggPk, cache, err := MusigAggregateKeys([]*PublicKey{pub1, pub2})
	if err != nil {
		t.Fatalf("MusigAggregateKeys failed: %v", err)
	}

	secnonce1, pubnonce1, err := MusigGenerateNonce(priv1, pub1, nil, nil, nil)
	if err != nil {
		t.Fatalf("MusigGenerateNonce failed: %v", err)
	}
	secnonce2, pubnonce2, err := MusigGenerateNonce(priv2, pub2, nil, nil, nil)
	if err != nil {
		t.Fatalf("MusigGenerateNonce failed: %v", err)
	}

	aggNonce, err := MusigAggregateNonces([]*MusigPubNonce{pubnonce1, pubnonce2})
	if err != nil {
		t.Fatalf("MusigAggregateNonces failed: %v", err)
	}

	session, err := MusigProcessNonce(aggNonce, musigTestDigest, cache)
	if err != nil {
		t.Fatalf("MusigProcessNonce failed: %v", err)
	}

	return musigTwoSignerSession{
		priv1: priv1, priv2: priv2, pub1: pub1, pub2: pub2,
		aggPk: aggPk, cache: cache,
		secnonce1: secnonce1, pubnonce1: pubnonce1,
		secnonce2: secnonce2, pubnonce2: pubnonce2,
		aggNonce: aggNonce, session: session,
	}
}

func TestMusigAggregateKeysOrderMatters(t *testing.T) {
	_, pub1 := musigKey(t, 1)
	_, pub2 := musigKey(t, 2)

	aggPk1, _, err := MusigAggregateKeys([]*PublicKey{pub1, pub2})
	if err != nil {
		t.Fatalf("MusigAggregateKeys failed: %v", err)
	}
	aggPk2, _, err := MusigAggregateKeys([]*PublicKey{pub2, pub1})
	if err != nil {
		t.Fatalf("MusigAggregateKeys failed: %v", err)
	}

	if aggPk1.Equal(aggPk2) {
		t.Error("MusigAggregateKeys gave the same result for two different key orders")
	}
}

func TestMusigAggregateKeysRejectsEmpty(t *testing.T) {
	if _, _, err := MusigAggregateKeys(nil); !errors.Is(err, ErrMusigKeyAggFailed) {
		t.Errorf("MusigAggregateKeys error = %v, want %v", err, ErrMusigKeyAggFailed)
	}
}

func TestMusigKeyaggCacheTweakAddMatchesPlainTweak(t *testing.T) {
	_, pub1 := musigKey(t, 1)
	_, pub2 := musigKey(t, 2)

	aggPk, cache, err := MusigAggregateKeys([]*PublicKey{pub1, pub2})
	if err != nil {
		t.Fatalf("MusigAggregateKeys failed: %v", err)
	}

	var tweak [32]byte
	tweak[31] = 7

	want, err := aggPk.TweakAdd(tweak)
	if err != nil {
		t.Fatalf("PublicKey.TweakAdd failed: %v", err)
	}
	got, err := cache.TweakAdd(tweak)
	if err != nil {
		t.Fatalf("MusigKeyaggCache.TweakAdd failed: %v", err)
	}

	if !got.Equal(want) {
		t.Error("MusigKeyaggCache.TweakAdd does not match PublicKey.TweakAdd on the aggregate key")
	}
}

func TestMusigPubNonceSerializeParseRoundTrip(t *testing.T) {
	_, pub := musigKey(t, 1)
	_, pubnonce, err := MusigGenerateNonce(nil, pub, nil, nil, nil)
	if err != nil {
		t.Fatalf("MusigGenerateNonce failed: %v", err)
	}

	wire := pubnonce.Bytes()
	parsed, err := ParseMusigPubNonce(wire[:])
	if err != nil {
		t.Fatalf("ParseMusigPubNonce failed: %v", err)
	}
	if parsed.Bytes() != wire {
		t.Error("ParseMusigPubNonce(pubnonce.Bytes()) does not round trip")
	}
}

func TestParseMusigPubNonceRejectsInvalid(t *testing.T) {
	var garbage [66]byte
	for i := range garbage {
		garbage[i] = 0xff
	}
	if _, err := ParseMusigPubNonce(garbage[:]); !errors.Is(err, ErrInvalidMusigPubNonce) {
		t.Errorf("ParseMusigPubNonce error = %v, want %v", err, ErrInvalidMusigPubNonce)
	}
}

func TestMusigAggNonceSerializeParseRoundTrip(t *testing.T) {
	s := newMusigTwoSignerSession(t)

	wire := s.aggNonce.Bytes()
	parsed, err := ParseMusigAggNonce(wire[:])
	if err != nil {
		t.Fatalf("ParseMusigAggNonce failed: %v", err)
	}
	if parsed.Bytes() != wire {
		t.Error("ParseMusigAggNonce(aggNonce.Bytes()) does not round trip")
	}
}

func TestMusigAggregateNoncesRejectsEmpty(t *testing.T) {
	if _, err := MusigAggregateNonces(nil); !errors.Is(err, ErrMusigNonceAggFailed) {
		t.Errorf("MusigAggregateNonces error = %v, want %v", err, ErrMusigNonceAggFailed)
	}
}

func TestMusigSecnonceReuseRejected(t *testing.T) {
	s := newMusigTwoSignerSession(t)

	if _, err := s.secnonce1.Sign(s.priv1, s.cache, s.session); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if _, err := s.secnonce1.Sign(s.priv1, s.cache, s.session); !errors.Is(err, ErrMusigSecnonceReused) {
		t.Errorf("second Sign on the same secnonce: error = %v, want %v", err, ErrMusigSecnonceReused)
	}
}

func TestMusigPartialSigSerializeParseRoundTrip(t *testing.T) {
	s := newMusigTwoSignerSession(t)

	sig1, err := s.secnonce1.Sign(s.priv1, s.cache, s.session)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	wire := sig1.Bytes()
	parsed, err := ParseMusigPartialSig(wire[:])
	if err != nil {
		t.Fatalf("ParseMusigPartialSig failed: %v", err)
	}
	if parsed.Bytes() != wire {
		t.Error("ParseMusigPartialSig(sig.Bytes()) does not round trip")
	}
}

func TestParseMusigPartialSigRejectsInvalid(t *testing.T) {
	var garbage [32]byte
	for i := range garbage {
		garbage[i] = 0xff
	}
	if _, err := ParseMusigPartialSig(garbage[:]); !errors.Is(err, ErrInvalidMusigPartialSig) {
		t.Errorf("ParseMusigPartialSig error = %v, want %v", err, ErrInvalidMusigPartialSig)
	}
}

func TestMusigVerifyPartialSigRejectsWrongPubnonceAndPubkey(t *testing.T) {
	s := newMusigTwoSignerSession(t)

	sig1, err := s.secnonce1.Sign(s.priv1, s.cache, s.session)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if !MusigVerifyPartialSig(sig1, s.pubnonce1, s.pub1, s.cache, s.session) {
		t.Error("MusigVerifyPartialSig rejected a partial signature it should accept")
	}
	if MusigVerifyPartialSig(sig1, s.pubnonce2, s.pub1, s.cache, s.session) {
		t.Error("MusigVerifyPartialSig accepted a signature checked against the wrong pubnonce")
	}
	if MusigVerifyPartialSig(sig1, s.pubnonce1, s.pub2, s.cache, s.session) {
		t.Error("MusigVerifyPartialSig accepted a signature checked against the wrong pubkey")
	}
}

func TestMusigAggregateSignaturesRejectsEmpty(t *testing.T) {
	s := newMusigTwoSignerSession(t)
	if _, err := MusigAggregateSignatures(s.session, nil); !errors.Is(err, ErrMusigSigAggFailed) {
		t.Errorf("MusigAggregateSignatures error = %v, want %v", err, ErrMusigSigAggFailed)
	}
}

// The capstone test: a complete 2-signer MuSig2 session, end to end, whose
// final output is a signature verified by the ordinary, protocol-agnostic
// VerifySchnorr — proving MuSig2's aggregate signature really is just a
// normal Schnorr signature over the aggregate key from the verifier's side.
func TestMusigFullSessionProducesValidSignature(t *testing.T) {
	s := newMusigTwoSignerSession(t)

	sig1, err := s.secnonce1.Sign(s.priv1, s.cache, s.session)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	sig2, err := s.secnonce2.Sign(s.priv2, s.cache, s.session)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if !MusigVerifyPartialSig(sig1, s.pubnonce1, s.pub1, s.cache, s.session) {
		t.Fatal("MusigVerifyPartialSig rejected signer 1's own partial signature")
	}
	if !MusigVerifyPartialSig(sig2, s.pubnonce2, s.pub2, s.cache, s.session) {
		t.Fatal("MusigVerifyPartialSig rejected signer 2's own partial signature")
	}

	finalSig, err := MusigAggregateSignatures(s.session, []*MusigPartialSig{sig1, sig2})
	if err != nil {
		t.Fatalf("MusigAggregateSignatures failed: %v", err)
	}

	if !VerifySchnorr(s.aggPk, musigTestDigest[:], finalSig[:]) {
		t.Error("the aggregated MuSig2 signature does not verify as an ordinary Schnorr signature over the aggregate key")
	}
}

func TestMusigGenerateNonceCounterUniqueness(t *testing.T) {
	priv, _ := musigKey(t, 1)

	secnonce1, pubnonce1, err := MusigGenerateNonceCounter(priv, 1, nil, nil, nil)
	if err != nil {
		t.Fatalf("MusigGenerateNonceCounter failed: %v", err)
	}
	secnonce2, pubnonce2, err := MusigGenerateNonceCounter(priv, 2, nil, nil, nil)
	if err != nil {
		t.Fatalf("MusigGenerateNonceCounter failed: %v", err)
	}

	if secnonce1.secnonce == secnonce2.secnonce || pubnonce1.pubnonce == pubnonce2.pubnonce {
		t.Error("MusigGenerateNonceCounter produced identical nonces for different counters")
	}
}
