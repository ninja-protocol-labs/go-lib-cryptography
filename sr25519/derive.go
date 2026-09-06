package sr25519

import "github.com/gtank/merlin"

// Substrate's hierarchical key derivation. Only two of schnorrkel's four
// combinations are exposed: soft derivation from a public key, the
// scheme's reason to exist, and hard derivation from a private key.
//
// Soft-deriving a private key is left out because schnorrkel produces an
// already-expanded (scalar ∥ nonce) SecretKey with no 32-byte form, which
// could never be re-expressed as a PrivateKey here. Hard-deriving a public
// key alone is impossible in the scheme.

// DeriveSoft derives the child public key for index under chainCode,
// returning it and its own chain code.
func (k *PublicKey) DeriveSoft(chainCode [ChainCodeLen]byte, index []byte) (*PublicKey, [ChainCodeLen]byte, error) {
	if k == nil {
		return nil, [ChainCodeLen]byte{}, ErrDeriveFailed
	}

	// The label and appending only the index are schnorrkel's convention.
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

// DeriveHard derives the child private key for index under chainCode,
// returning it and its own chain code.
func (k *PrivateKey) DeriveHard(chainCode [ChainCodeLen]byte, index []byte) (*PrivateKey, [ChainCodeLen]byte, error) {
	if k == nil {
		return nil, [ChainCodeLen]byte{}, ErrDeriveFailed
	}

	msk, newCC, err := k.secretKey().HardDeriveMiniSecretKey(index, chainCode)
	if err != nil {
		return nil, [ChainCodeLen]byte{}, ErrDeriveFailed
	}

	child, err := newPrivateKey(msk.ExpandEd25519().Encode())
	if err != nil {
		return nil, [ChainCodeLen]byte{}, ErrDeriveFailed
	}
	return child, newCC, nil
}
