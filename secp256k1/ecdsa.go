package secp256k1

// ECDSA signing and verification.
//
// Sign takes the raw message and hashes it internally (SHA-256); a separate
// digest-taking function is planned for callers who already have a
// pre-hashed 32-byte value (e.g. from another chain's rules) and must not
// hash it twice — these are kept as distinct functions rather than one
// function branching on an input-shape flag.
//
// TODO:
//   func Sign(priv *PrivateKey, msg []byte) (sig []byte, err error)
//   func SignDigest(priv *PrivateKey, digest [32]byte) (sig []byte, err error)
//   func Verify(pub *PublicKey, msg, sig []byte) bool
//   func VerifyDigest(pub *PublicKey, digest [32]byte, sig []byte) bool
//   (DER vs compact encoding, hedged signing, and recovery are additional
//   decisions to make when these are filled in.)
