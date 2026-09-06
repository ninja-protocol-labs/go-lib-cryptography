package secp256r1

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"math/big"

	"github.com/ninja-protocol-labs/go-lib-cryptography/encoding"
)

type PublicKey struct {
	key [PubkeyCompressedLen]byte

	// unc is the uncompressed form. Recovering it from key means a
	// modular square root, which Verify and ECDH would otherwise pay on
	// every call.
	unc [PubkeyUncompressedLen]byte
}

// PublicKeyFromBytes takes a compressed or uncompressed SEC 1 point and
// stores it compressed.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	var k [PubkeyCompressedLen]byte

	var x, y *big.Int

	switch len(b) {
	case PubkeyCompressedLen:
		if x, y = elliptic.UnmarshalCompressed(curve(), b); x == nil {
			return nil, ErrInvalidPublicKey
		}

	case PubkeyUncompressedLen:
		// NewPublicKey does the on-curve and not-at-infinity checks;
		// splitUncompressed then parses bytes already known good.
		if _, err := ecdh.P256().NewPublicKey(b); err != nil {
			return nil, ErrInvalidPublicKey
		}
		x, y = splitUncompressed(b)

	default:
		return nil, ErrInvalidPublicKey
	}

	copy(k[:], elliptic.MarshalCompressed(curve(), x, y))
	return &PublicKey{
		key: k,
		unc: joinUncompressed(x, y),
	}, nil
}

func (k *PublicKey) Bytes() [PubkeyCompressedLen]byte {
	return k.key
}

func (k *PublicKey) BytesUncompressed() [PubkeyUncompressedLen]byte {
	return k.unc
}

func (k *PublicKey) Equal(o *PublicKey) bool {
	if o == nil {
		return false
	}
	return k.key == o.key
}

func (k *PublicKey) IsZero() bool {
	return k == nil || *k == PublicKey{}
}

func (k *PublicKey) String() string {
	return encoding.Hex.Encode(k.key[:])
}
