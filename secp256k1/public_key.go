package secp256k1

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

// PublicKey is a point on secp256k1, stored compressed whichever encoding
// it was parsed from.
type PublicKey struct {
	key [PubkeyCompressedLen]byte
}

// PublicKeyFromBytes takes a compressed or uncompressed SEC 1 point and
// stores it compressed.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	var k [PubkeyCompressedLen]byte

	if len(b) != PubkeyCompressedLen && len(b) != PubkeyUncompressedLen {
		return nil, ErrInvalidPublicKey
	}

	p, err := secp256k1.ParsePubKey(b)
	if err != nil {
		return nil, ErrInvalidPublicKey
	}

	copy(k[:], p.SerializeCompressed())
	return &PublicKey{
		key: k,
	}, nil
}

// Bytes returns the compressed SEC 1 encoding — a parity byte and X — as
// a copy. This is the form the key is stored in, so it round-trips
// through PublicKeyFromBytes unchanged.
func (k *PublicKey) Bytes() [PubkeyCompressedLen]byte {
	return k.key
}

// BytesUncompressed returns the uncompressed SEC 1 encoding: 0x04, X, Y.
// Ethereum hashes the 64 bytes after that prefix to derive an address.
//
// Unlike Bytes this recomputes Y from the stored point on every call.
func (k *PublicKey) BytesUncompressed() [PubkeyUncompressedLen]byte {
	var b [PubkeyUncompressedLen]byte

	copy(b[:], k.point().SerializeUncompressed())
	return b
}

// Equal reports whether o is the same point. It is nil-safe, and compares
// the compressed form, so two keys parsed from different encodings of the
// same point are equal.
func (k *PublicKey) Equal(o *PublicKey) bool {
	if o == nil {
		return false
	}
	return k.key == o.key
}

// IsZero catches a `var k PublicKey`; no constructor returns one.
func (k *PublicKey) IsZero() bool {
	return k == nil || *k == PublicKey{}
}

// String returns the compressed encoding as lowercase hex.
func (k *PublicKey) String() string {
	return encoding.Hex.Encode(k.key[:])
}

// point is k in the form dcrd's verification takes; k.key parsed at
// construction, so the error cannot fire.
func (k *PublicKey) point() *secp256k1.PublicKey {
	p, _ := secp256k1.ParsePubKey(k.key[:])
	return p
}
