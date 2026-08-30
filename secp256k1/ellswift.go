package secp256k1

// ElligatorSwift point encoding: representing a public key as 64 bytes
// indistinguishable from uniform randomness, and the x-only ECDH variant
// built on it.
//
// TODO:
//   func (pub *PublicKey) EllswiftEncode(rnd [32]byte) ([64]byte, error)
//   func EllswiftDecode(encoded [64]byte) *PublicKey
//   func EllswiftCreate(priv *PrivateKey, auxRand *[32]byte) ([64]byte, error)
//   func EllswiftECDH(ellA, ellB [64]byte, priv *PrivateKey, isPartyB bool) ([32]byte, error)
