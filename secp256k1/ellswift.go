package secp256k1

import "github.com/ninja-protocol-labs/go-lib-cryptography/secp256k1/internal"

// ElligatorSwift point encoding: representing a public key as 64 bytes
// indistinguishable from uniform randomness, and the x-only Diffie-Hellman
// variant built on it.
//
// The encoding is not a canonical serialization: encoding the same key
// twice (even with the same randomness input) is not guaranteed to produce
// the same 64 bytes across library versions. Bytes()/BytesUncompressed()
// remain the stable, canonical form; this is for contexts that specifically
// need a key to look indistinguishable from random.

// EllswiftEncode re-encodes k as 64 bytes indistinguishable from uniform
// randomness. rnd selects among the encoding's several valid
// representations for the same point.
func (k *PublicKey) EllswiftEncode(rnd [32]byte) ([64]byte, error) {
	ell, ok := internal.EllswiftEncode(k.key[:], &rnd)
	if !ok {
		return [64]byte{}, ErrEllswiftFailed
	}
	return ell, nil
}

// EllswiftEncode derives the ElligatorSwift encoding of k's public key
// directly, without deriving and then encoding a PublicKey separately.
// auxRand is optional extra entropy for the encoding, not for the key
// itself; pass nil to omit it.
func (k *PrivateKey) EllswiftEncode(auxRand *[32]byte) ([64]byte, error) {
	ell, ok := internal.EllswiftCreate(&k.key, auxRand)
	if !ok {
		return [64]byte{}, ErrEllswiftFailed
	}
	return ell, nil
}

// EllswiftDecode decodes an EllswiftEncode-produced encoding back to a
// public key. Every 64-byte input decodes to some valid point, so this
// cannot fail.
func EllswiftDecode(encoded [64]byte) *PublicKey {
	return &PublicKey{
		key: internal.EllswiftDecodeCompressed(&encoded),
	}
}

// EllswiftECDH computes the shared secret between two ElligatorSwift-encoded
// points, using k as one side of the exchange. ellA and ellB are fixed
// roles, not self/peer — isPartyB says which one k's key corresponds to (0
// for A, 1 for B), and that correspondence is the caller's own
// responsibility to get right: passing it backwards computes a different,
// wrong secret rather than failing.
func (k *PrivateKey) EllswiftECDH(ellA, ellB [64]byte, isPartyB bool) ([32]byte, error) {
	secret, ok := internal.EllswiftECDH(&ellA, &ellB, &k.key, isPartyB)
	if !ok {
		return [32]byte{}, ErrECDHFailed
	}
	return secret, nil
}
