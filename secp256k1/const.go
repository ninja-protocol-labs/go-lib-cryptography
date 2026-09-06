package secp256k1

const (
	SeckeyLen             = 32
	PubkeyCompressedLen   = 33
	PubkeyUncompressedLen = 65
	DigestLen             = 32
	SignatureCompactLen   = 64
	SignatureScalarLen    = 32
	RecoveryIDMax         = 3
)

// dcrd packs a recoverable signature as <27+id+4><R><S>, where the +4
// marks a compressed key.
const compactRecoveryBase = 27 + 4
