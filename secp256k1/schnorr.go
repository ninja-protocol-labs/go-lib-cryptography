package secp256k1

// Schnorr signing and verification (the scheme internal.SchnorrSign/Verify
// bind), over x-only public keys.
//
// TODO:
//   func SignSchnorr(priv *PrivateKey, msg []byte) (sig []byte, err error)
//   func VerifySchnorr(pub *PublicKey, msg, sig []byte) bool
//   (x-only key exposure/conversion on PublicKey, and hedged signing, are
//   additional decisions to make when these are filled in.)
