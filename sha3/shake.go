package sha3

import "crypto/sha3"

// The extendable-output half of FIPS 202, plus cSHAKE from SP 800-185.
//
// The number in a SHAKE's name is a security level, not an output length:
// SHAKE128 gives 128-bit security against collisions and preimages no
// matter how many bytes you read, and reading fewer than 32 gives you less
// than that. It is not "SHAKE with a 128-bit output".

// HashSHAKE128 returns length bytes of SHAKE128 output over data.
//
// This and HashSHAKE256 are the only functions in this package returning a
// slice rather than a Digest, and for exactly the reason the module's
// convention reserves that for: the output length is the caller's choice,
// so it genuinely is not knowable from the type.
func HashSHAKE128(data []byte, length int) []byte {
	return sha3.SumSHAKE128(data, length)
}

// HashSHAKE256 returns length bytes of SHAKE256 output over data.
func HashSHAKE256(data []byte, length int) []byte {
	return sha3.SumSHAKE256(data, length)
}

// SHAKE is an extendable-output function: absorb any amount of input with
// Write, then squeeze any amount of output with Read.
//
// The output is one stream, not a digest recomputed per length — a caller
// that reads 100 bytes gets the same first 32 as one that stopped at 32.
// Write after the first Read is not allowed; see Write.
type SHAKE struct {
	s    *sha3.SHAKE
	read bool
}

// NewSHAKE128 returns a SHAKE128 XOF.
func NewSHAKE128() *SHAKE {
	return &SHAKE{s: sha3.NewSHAKE128()}
}

// NewSHAKE256 returns a SHAKE256 XOF.
func NewSHAKE256() *SHAKE {
	return &SHAKE{s: sha3.NewSHAKE256()}
}

// NewCSHAKE128 returns a cSHAKE128 XOF, domain-separated by a function
// name n and a customization string s (SP 800-185's N and S).
//
// Two cSHAKEs with different n or s produce unrelated output for the same
// input, which is what makes cSHAKE the right primitive when one XOF has
// to serve several purposes in a protocol. With both empty it is defined
// to be plain SHAKE128, so passing neither defeats the point.
func NewCSHAKE128(n, s []byte) *SHAKE {
	return &SHAKE{s: sha3.NewCSHAKE128(n, s)}
}

// NewCSHAKE256 returns a cSHAKE256 XOF. See NewCSHAKE128 on n and s.
func NewCSHAKE256(n, s []byte) *SHAKE {
	return &SHAKE{s: sha3.NewCSHAKE256(n, s)}
}

// Write absorbs more input. Once the sponge has switched to squeezing —
// at the first Read — it returns ErrWriteAfterRead without absorbing
// anything, since absorbing into a squeezing sponge would produce a
// stream no other implementation agrees with.
//
// The underlying implementation panics in that situation; this reports it
// instead, as everything else in this module does.
func (x *SHAKE) Write(p []byte) (int, error) {
	if x.read {
		return 0, ErrWriteAfterRead
	}
	return x.s.Write(p)
}

// Read squeezes len(p) bytes of output. It never returns an error and
// never a short read: an XOF's stream has no end.
func (x *SHAKE) Read(p []byte) (int, error) {
	x.read = true
	return x.s.Read(p)
}

// Reset returns x to its initial state, keeping the function name and
// customization string a cSHAKE was constructed with.
func (x *SHAKE) Reset() {
	x.s.Reset()
	x.read = false
}

// BlockSize returns the sponge's rate in bytes.
func (x *SHAKE) BlockSize() int {
	return x.s.BlockSize()
}
