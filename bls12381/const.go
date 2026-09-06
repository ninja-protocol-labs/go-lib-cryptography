package bls12381

const (
	SeckeyLen = 32

	G1CompressedLen = 48
	G2CompressedLen = 96

	// GTLen is a 𝔾ₜ element: 12 𝔽p coordinates of 48 bytes.
	GTLen = 12 * 48

	PubkeyMinPkLen  = G1CompressedLen
	PubkeyMinSigLen = G2CompressedLen

	SignatureMinPkLen  = G2CompressedLen
	SignatureMinSigLen = G1CompressedLen
)

// Ciphersuite IDs from draft-irtf-cfrg-bls-signature, basic scheme (_NUL_:
// no message augmentation, no proof of possession).
const (
	DefaultDSTMinPk  = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
	DefaultDSTMinSig = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
)
