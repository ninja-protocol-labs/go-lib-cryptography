package blake3

import "lukechampine.com/blake3"

// BLAKE3's third mode: turning one key into any number of independent
// subkeys, each bound to a context string.
//
// The context is a domain separator, not a salt. It should be a hardcoded,
// globally unique, application-specific constant — the specification's own
// advice is a string like
// "example.com 2019-12-25 16:18:03 session tokens v1" — and it must not
// be attacker-controlled or derived from the material. Two different
// contexts over the same material give unrelated keys; the same context
// always gives the same key.

// DeriveKey derives a KeyLen-byte subkey from material under context.
//
// material must already be a strong key — this mode separates keys, it
// does not stretch them. Passing a password here derives a subkey no
// harder to guess than the password was; use a password hash first.
func DeriveKey(context string, material []byte) [KeyLen]byte {
	var out [KeyLen]byte
	blake3.DeriveKey(out[:], context, material)
	return out
}

// DeriveKeyN derives an n-byte subkey from material under context, for
// the cases where KeyLen is not the length wanted — an AEAD key and nonce
// derived together, say.
//
// It returns a slice rather than an array because the length is the
// caller's, which is the one thing this module's array convention
// reserves a slice for. The first KeyLen bytes are exactly what DeriveKey
// returns, since every length is a prefix of the same stream.
func DeriveKeyN(context string, material []byte, n int) ([]byte, error) {
	if n < 1 {
		return nil, ErrInvalidSize
	}
	out := make([]byte, n)
	blake3.DeriveKey(out, context, material)
	return out, nil
}
