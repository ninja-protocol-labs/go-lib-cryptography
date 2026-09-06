// Package bn254bls implements BLS signatures — Boneh-Lynn-Shacham — on
// the BN254 curve. The two BLSes are unrelated: the curve is named for
// Barreto, Lynn and Scott, the signature scheme for Boneh, Lynn and
// Shacham, and only Ben Lynn appears in both.
//
// A signature is a single group element and aggregates: any number of
// signatures over the same message combine into one of the same size,
// which is what the scheme is for and what ECDSA cannot do. The price is
// that there is no public key recovery — a signature is sk·H(m), and
// extracting sk from it is the discrete log problem — so the public key
// must be carried or referenced separately.
//
// The curve arithmetic these signatures are built on lives in bn254.
package bn254bls

const (
	// SeckeyLen is the byte length of a private key: a big-endian scalar
	// modulo r, the group order.
	SeckeyLen = 32

	// PubkeyMinPkLen is a compressed G1 point; PubkeyMinSigLen a
	// compressed G2 point.
	PubkeyMinPkLen  = 32
	PubkeyMinSigLen = 64

	// SignatureMinPkLen and SignatureMinSigLen are the two signature
	// lengths: a signature lives in whichever group the scheme did not
	// give the public key, so each is the other scheme's public key
	// length.
	SignatureMinPkLen  = PubkeyMinSigLen
	SignatureMinSigLen = PubkeyMinPkLen
)

// Ciphersuite IDs from draft-irtf-cfrg-bls-signature, basic scheme (_NUL_:
// no message augmentation, no proof of possession).
const (
	DefaultDSTMinPk  = "BLS_SIG_BN254G2_XMD:SHA-256_SVDW_RO_NUL_"
	DefaultDSTMinSig = "BLS_SIG_BN254G1_XMD:SHA-256_SVDW_RO_NUL_"
)
