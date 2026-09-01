// Package secp256r1 is the public API for the secp256r1 (NIST P-256) curve.
//
// Unlike secp256k1, Go's standard library already implements this curve
// (crypto/ecdsa, crypto/ecdh) with an audited, constant-time implementation
// — so there is no cgo boundary here, no vendored C library, and no
// internal package. This is a thin wrapper over the standard library,
// keeping the same PrivateKey/PublicKey shape and conventions as the
// secp256k1 package.
//
// Key validation, generation, and signing all go through crypto/ecdsa's own
// raw-key functions (ParseRawPrivateKey, PrivateKey.Bytes, GenerateKey),
// which do the same SEC 1 validation crypto/ecdh does — keeping this file
// to one stdlib package rather than mixing it with ecdh avoids the mental
// overhead of two parallel key types for what is, here, the same key.
// crypto/ecdh is used only in ecdh.go, where the actual Diffie-Hellman
// computation needs it.
//
// Direct use of crypto/elliptic's curve arithmetic (ScalarMult, Add, ...) is
// deprecated; this package never calls it. The only crypto/elliptic use is
// MarshalCompressed/UnmarshalCompressed for PublicKey's compressed encoding
// — pure point-encoding conversions, not arithmetic, and (unlike Marshal/
// Unmarshal, which carry their own "use crypto/ecdh instead" deprecation
// notice) neither carries any deprecation notice itself. Converting between
// that compressed form and the uncompressed SEC1 form crypto/ecdsa and
// crypto/ecdh deal in is done by hand (splitUncompressed/joinUncompressed
// below) rather than via the deprecated elliptic.Unmarshal/Marshal.
package secp256r1

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

// splitUncompressed extracts the X, Y coordinates from an uncompressed SEC1
// encoding (0x04 || X || Y). It performs no validation of its own — callers
// must already have established b is a well-formed, on-curve point (e.g.
// via crypto/ecdsa's own PublicKey.Bytes, or crypto/ecdh's NewPublicKey)
// before calling this; it exists only to avoid the deprecated
// elliptic.Unmarshal for that conversion.
func splitUncompressed(b []byte) (x, y *big.Int) {
	x = new(big.Int).SetBytes(b[1:33])
	y = new(big.Int).SetBytes(b[33:65])
	return x, y
}

// joinUncompressed builds the uncompressed SEC1 encoding (0x04 || X || Y)
// of the point (x, y). Like splitUncompressed, it performs no on-curve
// validation of its own — callers must already know (x, y) is a valid
// point (e.g. via elliptic.UnmarshalCompressed, which does validate) —
// and exists only to avoid the deprecated elliptic.Marshal.
func joinUncompressed(x, y *big.Int) [PubkeyUncompressedLen]byte {
	var out [PubkeyUncompressedLen]byte
	out[0] = 4
	x.FillBytes(out[1:33])
	y.FillBytes(out[33:65])
	return out
}

const (
	// SeckeyLen is the byte length of a PrivateKey's scalar.
	SeckeyLen = 32

	// PubkeyCompressedLen is the byte length of PublicKey's canonical
	// (compressed) encoding.
	PubkeyCompressedLen = 33

	// PubkeyUncompressedLen is the byte length of PublicKey's uncompressed
	// encoding.
	PubkeyUncompressedLen = 65

	// SignatureCompactLen is the byte length of a compact (r ∥ s)
	// signature. DER has no constant of its own: that encoding is
	// variable-length, which is why SignDER returns a slice where
	// SignCompact returns an array.
	SignatureCompactLen = 2 * SeckeyLen
)

func curve() elliptic.Curve { return elliptic.P256() }

// PrivateKey is a secp256r1 scalar in [1, n-1].
type PrivateKey struct {
	key [SeckeyLen]byte
}

// GeneratePrivateKey draws a random private key.
func GeneratePrivateKey() (*PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(curve(), rand.Reader)
	if err != nil {
		return nil, err
	}
	b, err := priv.Bytes()
	if err != nil {
		return nil, err
	}
	var key [SeckeyLen]byte
	copy(key[:], b)
	return &PrivateKey{
		key: key,
	}, nil
}

// PrivateKeyFromBytes parses a 32-byte scalar, verifying it decodes to a
// value in [1, n-1] via crypto/ecdsa's own validation (SEC 1, Section
// 2.3.6).
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if len(b) != SeckeyLen {
		return nil, ErrInvalidPrivateKey
	}
	if _, err := ecdsa.ParseRawPrivateKey(curve(), b); err != nil {
		return nil, ErrInvalidPrivateKey
	}
	var key [SeckeyLen]byte
	copy(key[:], b)
	return &PrivateKey{
		key: key,
	}, nil
}

// Bytes returns the 32-byte scalar.
func (k *PrivateKey) Bytes() [SeckeyLen]byte {
	return k.key
}

// PublicKey derives the public key corresponding to k. An error here would
// mean k's scalar, despite having passed validation at construction, no
// longer validates — not something normal operation can produce, but
// reported rather than assumed impossible.
func (k *PrivateKey) PublicKey() (*PublicKey, error) {
	priv, err := ecdsa.ParseRawPrivateKey(curve(), k.key[:])
	if err != nil {
		return nil, ErrPublicKeyDerivationFailed
	}
	// priv.PublicKey.Bytes(), not the deprecated X/Y fields directly. The
	// bytes it returns are already a validated uncompressed SEC1 point, so
	// splitUncompressed's lack of its own validation is fine here.
	uncompressed, err := priv.PublicKey.Bytes()
	if err != nil {
		return nil, ErrPublicKeyDerivationFailed
	}
	x, y := splitUncompressed(uncompressed)
	var pk [PubkeyCompressedLen]byte
	copy(pk[:], elliptic.MarshalCompressed(curve(), x, y))
	return &PublicKey{
		key: pk,
	}, nil
}

// Equal reports whether k and other are the same key.
func (k *PrivateKey) Equal(other *PrivateKey) bool {
	if other == nil {
		return false
	}
	return k.key == other.key
}

// PublicKey is a point on the secp256r1 curve.
type PublicKey struct {
	key [PubkeyCompressedLen]byte
}

// PublicKeyFromBytes parses a compressed (33-byte) or uncompressed (65-byte)
// public key, verifying it is a valid point on the curve. The internal
// representation is always compressed; the original form does not affect
// equality or later serialization.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	var x, y *big.Int
	switch len(b) {
	case PubkeyCompressedLen:
		x, y = elliptic.UnmarshalCompressed(curve(), b)
		if x == nil {
			return nil, ErrInvalidPublicKey
		}
	case PubkeyUncompressedLen:
		// crypto/ecdh.NewPublicKey does the on-curve/not-at-infinity
		// validation elliptic.Unmarshal would have (and is the
		// non-deprecated way to get it for an uncompressed SEC1 point);
		// splitUncompressed then just parses the now-trusted bytes.
		if _, err := ecdh.P256().NewPublicKey(b); err != nil {
			return nil, ErrInvalidPublicKey
		}
		x, y = splitUncompressed(b)
	default:
		return nil, ErrInvalidPublicKey
	}

	var pk [PubkeyCompressedLen]byte
	copy(pk[:], elliptic.MarshalCompressed(curve(), x, y))
	return &PublicKey{
		key: pk,
	}, nil
}

// point returns k's point, decoded from its stored compressed encoding.
func (k *PublicKey) point() (x, y *big.Int, err error) {
	x, y = elliptic.UnmarshalCompressed(curve(), k.key[:])
	if x == nil {
		return nil, nil, ErrPublicKeySerializationFailed
	}
	return x, y, nil
}

// Bytes returns the 33-byte compressed encoding.
func (k *PublicKey) Bytes() [PubkeyCompressedLen]byte {
	return k.key
}

// BytesUncompressed returns the 65-byte uncompressed encoding. An error here
// would mean k's compressed point, despite being validated at construction,
// cannot be decoded — not something normal operation can produce, but
// reported rather than assumed impossible.
func (k *PublicKey) BytesUncompressed() ([PubkeyUncompressedLen]byte, error) {
	x, y, err := k.point()
	if err != nil {
		return [PubkeyUncompressedLen]byte{}, err
	}
	return joinUncompressed(x, y), nil
}

// Equal reports whether k and other are the same point.
func (k *PublicKey) Equal(other *PublicKey) bool {
	if other == nil {
		return false
	}
	return k.key == other.key
}
