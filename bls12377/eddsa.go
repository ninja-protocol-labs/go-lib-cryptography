package bls12377

import (
	"bytes"
	"crypto/rand"
	"hash"

	gnarkeddsa "github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards/eddsa"
)

// EdDSA over the twisted Edwards curve embedded in BLS12-377's *scalar*
// field 𝔽r, not over BLS12-377 itself. Like the ECDSA above, its reason
// to exist is in-circuit verification: a gnark circuit over BLS12-377
// does this inner curve's arithmetic natively, and Ed25519 arithmetic
// only at great cost.
//
// Two things differ from RFC 8032's Ed25519, and both are visible in this
// API:
//
//   - There is no built-in message hash. gnark's EdDSA signs a sequence of
//     field elements, and the Fiat-Shamir challenge H(R, A, M) is computed
//     with a caller-supplied hash — MiMC over 𝔽r, in gnark's own circuits,
//     because it is the cheap one to prove. So SignEdDSA and VerifyEdDSA
//     both take a hash.Hash, and both fail without one.
//   - The private key does not round-trip through its seed. The scalar and
//     the nonce source are derived from the seed by BLAKE2b and the seed is
//     then discarded, so Bytes returns gnark-crypto's own
//     (public key ∥ scalar ∥ nonce source) form, not the 32 bytes that
//     produced it. Use EdDSAPrivateKeyFromSeed when you need to regenerate
//     a key deterministically from stored entropy.
//
// These signatures interoperate with gnark's std/signature/eddsa gadget
// and with nothing else.

const (
	// EdDSASeedLen is the byte length of the seed EdDSAPrivateKeyFromSeed
	// expands into a key pair.
	EdDSASeedLen = 32

	// EdDSAPrivkeyLen is the byte length of an EdDSAPrivateKey's
	// serialization: public key ∥ scalar ∥ nonce source.
	EdDSAPrivkeyLen = 3 * SeckeyLen

	// EdDSAPubkeyLen is the byte length of a compressed point on the
	// embedded twisted Edwards curve.
	EdDSAPubkeyLen = SeckeyLen

	// EdDSASignatureLen is the byte length of a signature: R ∥ S.
	EdDSASignatureLen = 2 * SeckeyLen
)

// EdDSAPrivateKey is a signing key on BLS12-377's embedded twisted
// Edwards curve.
type EdDSAPrivateKey struct {
	key gnarkeddsa.PrivateKey
}

// GenerateEdDSAPrivateKey draws a random EdDSA key pair.
func GenerateEdDSAPrivateKey() (*EdDSAPrivateKey, error) {
	k, err := gnarkeddsa.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &EdDSAPrivateKey{key: *k}, nil
}

// EdDSAPrivateKeyFromSeed expands a 32-byte seed into a key pair,
// deterministically: the scalar and the nonce source are the two halves of
// BLAKE2b-512(seed), with RFC 8032's clamping applied to the scalar. The
// same seed always yields the same key.
func EdDSAPrivateKeyFromSeed(seed []byte) (*EdDSAPrivateKey, error) {
	if len(seed) != EdDSASeedLen {
		return nil, ErrInvalidPrivateKey
	}
	k, err := gnarkeddsa.GenerateKey(bytes.NewReader(seed))
	if err != nil {
		return nil, ErrInvalidPrivateKey
	}
	return &EdDSAPrivateKey{key: *k}, nil
}

// EdDSAPrivateKeyFromBytes parses the serialization Bytes produces:
// public key ∥ scalar ∥ nonce source. The scalar's clamping and its
// agreement with the public key are both checked.
func EdDSAPrivateKeyFromBytes(b []byte) (*EdDSAPrivateKey, error) {
	if len(b) != EdDSAPrivkeyLen {
		return nil, ErrInvalidPrivateKey
	}
	var k gnarkeddsa.PrivateKey
	if _, err := k.SetBytes(b); err != nil {
		return nil, ErrInvalidPrivateKey
	}
	return &EdDSAPrivateKey{key: k}, nil
}

// Bytes returns public key ∥ scalar ∥ nonce source.
func (k *EdDSAPrivateKey) Bytes() [EdDSAPrivkeyLen]byte {
	var out [EdDSAPrivkeyLen]byte
	copy(out[:], k.key.Bytes())
	return out
}

// PublicKey derives the public key corresponding to k.
func (k *EdDSAPrivateKey) PublicKey() *EdDSAPublicKey {
	return &EdDSAPublicKey{key: k.key.PublicKey}
}

// Equal reports whether k and other are the same key.
func (k *EdDSAPrivateKey) Equal(other *EdDSAPrivateKey) bool {
	if other == nil {
		return false
	}
	return k.Bytes() == other.Bytes()
}

// EdDSAPublicKey is a point on the embedded twisted Edwards curve, used
// to verify EdDSA signatures.
type EdDSAPublicKey struct {
	key gnarkeddsa.PublicKey
}

// EdDSAPublicKeyFromBytes parses a compressed point on the embedded
// twisted Edwards curve, checking that it is on the curve, is not the
// identity, and lies in the prime-order subgroup.
//
// gnark-crypto's SetBytes already rejects the identity and anything
// outside the prime-order subgroup. The on-curve check is this package's
// addition: SetBytes recovers x from y through the curve equation and
// does not report a failed square root, so a bad y yields a point that is
// simply not on the curve, and the subgroup test it then runs is only
// meaningful for points that are.
func EdDSAPublicKeyFromBytes(b []byte) (*EdDSAPublicKey, error) {
	if len(b) != EdDSAPubkeyLen {
		return nil, ErrInvalidPublicKey
	}
	var k gnarkeddsa.PublicKey
	if _, err := k.SetBytes(b); err != nil {
		return nil, ErrInvalidPublicKey
	}
	if !k.A.IsOnCurve() || k.A.IsZero() || !k.A.IsInSubGroup() {
		return nil, ErrInvalidPublicKey
	}
	return &EdDSAPublicKey{key: k}, nil
}

// Bytes returns the compressed public key.
func (k *EdDSAPublicKey) Bytes() [EdDSAPubkeyLen]byte {
	var out [EdDSAPubkeyLen]byte
	copy(out[:], k.key.Bytes())
	return out
}

// Equal reports whether k and other are the same key.
func (k *EdDSAPublicKey) Equal(other *EdDSAPublicKey) bool {
	if other == nil {
		return false
	}
	return k.key.Equal(&other.key)
}

// SignEdDSA signs msg with priv, returning R ∥ S.
//
// hFunc computes the Fiat-Shamir challenge and is required — there is no
// default, and no sensible one: it has to be the same hash the verifier
// (in a circuit, the gadget) uses, which is a choice about the proving
// system, not about this signature.
func SignEdDSA(priv *EdDSAPrivateKey, msg []byte, hFunc hash.Hash) ([EdDSASignatureLen]byte, error) {
	var out [EdDSASignatureLen]byte
	if priv == nil {
		return out, ErrInvalidPrivateKey
	}
	if hFunc == nil {
		return out, ErrHashRequired
	}
	sig, err := priv.key.Sign(msg, hFunc)
	if err != nil {
		return out, ErrSigningFailed
	}
	copy(out[:], sig)
	return out, nil
}

// VerifyEdDSA checks an R ∥ S signature against pub and msg. hFunc must be
// the same hash SignEdDSA was given.
func VerifyEdDSA(pub *EdDSAPublicKey, msg, sig []byte, hFunc hash.Hash) bool {
	if pub == nil || hFunc == nil || len(sig) != EdDSASignatureLen {
		return false
	}
	ok, err := pub.key.Verify(sig, msg, hFunc)
	return err == nil && ok
}
