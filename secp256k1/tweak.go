package secp256k1

// Key tweaking: additive/multiplicative derivation (e.g. BIP32-style child
// keys) and x-only tweaking, over PrivateKey/PublicKey.
//
// TODO:
//   func (priv *PrivateKey) TweakAdd(tweak [32]byte) (*PrivateKey, error)
//   func (priv *PrivateKey) TweakMul(tweak [32]byte) (*PrivateKey, error)
//   func (pub *PublicKey) TweakAdd(tweak [32]byte) (*PublicKey, error)
//   func (pub *PublicKey) TweakMul(tweak [32]byte) (*PublicKey, error)
//   func (pub *PublicKey) Negate() *PublicKey
//   func (priv *PrivateKey) Negate() *PrivateKey
//   (x-only variants of tweak-add, for Taproot-style output-key
//   construction, are an additional decision — likely their own type rather
//   than overloading PublicKey.)
