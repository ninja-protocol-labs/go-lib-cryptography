package sr25519

import (
	"github.com/gtank/merlin"
)

// Hierarchical key derivation (Substrate/Polkadot's HDKD scheme, "soft"
// and "hard" derivation from a chain code and an arbitrary index).
//
// Only two of the four combinations schnorrkel supports are exposed here,
// by design rather than oversight:
//
//   - PublicKey.DeriveSoft: soft derivation from a public key alone — the
//     scheme's actual reason to exist (deriving a family of related
//     accounts without the private key).
//   - PrivateKey.DeriveHard: hard derivation from a private key.
//     schnorrkel implements this as producing a brand-new MiniSecretKey
//     (seed); this package immediately expands that into the scalar form
//     PrivateKey actually stores (see key.go's package doc), the same
//     step GeneratePrivateKey performs on a freshly random seed.
//
// Soft-deriving a *private* key is deliberately not exposed: schnorrkel
// implements it as producing an already-expanded (scalar || nonce)
// SecretKey with no equivalent 32-byte seed encoding — it can never be
// re-expressed as a PrivateKey the way every other key in this package
// can. Adding it would mean introducing a second, seedless private-key
// type solely for this one case; given this package's narrower scope
// relative to secp256k1 already, that trade-off isn't taken here. Hard
// deriving a public key alone is impossible in this scheme (it needs the
// private scalar), so schnorrkel doesn't offer it either.

// DeriveSoft derives a child public key identified by index under
// chainCode, returning the child key and its own chain code (for further
// derivation).
func (k *PublicKey) DeriveSoft(chainCode [ChainCodeLen]byte, index []byte) (*PublicKey, [ChainCodeLen]byte, error) {
	// schnorrkel's own "simple"/"soft" HDKD transcript (see
	// DeriveKeySimple in go-schnorrkel) — the label "SchnorrRistrettoHDKD"
	// and appending only the index is schnorrkel's convention, not one
	// this package invents.
	t := merlin.NewTranscript("SchnorrRistrettoHDKD")
	t.AppendMessage([]byte("sign-bytes"), index)

	ext, err := k.schnorrkelKey().DeriveKey(t, chainCode)
	if err != nil {
		return nil, [ChainCodeLen]byte{}, ErrDeriveFailed
	}
	child, err := ext.Public()
	if err != nil {
		return nil, [ChainCodeLen]byte{}, ErrDeriveFailed
	}
	return &PublicKey{
		key: child.Encode(),
	}, ext.ChainCode(), nil
}

// DeriveHard derives a child private key identified by index under
// chainCode, returning the child key and its own chain code (for further
// derivation).
func (k *PrivateKey) DeriveHard(chainCode [ChainCodeLen]byte, index []byte) (*PrivateKey, [ChainCodeLen]byte, error) {
	msk, newCC, err := k.secretKey().HardDeriveMiniSecretKey(index, chainCode)
	if err != nil {
		return nil, [ChainCodeLen]byte{}, ErrDeriveFailed
	}
	return &PrivateKey{
		key: msk.ExpandEd25519().Encode(),
	}, newCC, nil
}
