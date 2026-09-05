// Package scrypt is the public API for scrypt, the memory-hard password-based
// key derivation function of RFC 7914 and Colin Percival's 2009 paper
// "Stronger Key Derivation via Sequential Memory-Hard Functions".
//
// # Memory is the point
//
// pbkdf2 makes a guess cost CPU time and nothing else, so an attacker with a
// GPU or an ASIC gains against a defender with a CPU at the full ratio of
// their throughputs. scrypt makes each guess also cost MemoryBytes(N, r) bytes
// of RAM, filled and re-read in an order that cannot be known ahead of time.
// Silicon that is cheap to parallelise is not cheap to give memory to, so the
// attacker's advantage collapses to something near the ratio of their memory
// budgets.
//
// That is the whole design, and it is why the parameters look the way they do.
//
// # The parameters
//
//   - N is the cost: the number of blocks held in memory, and the number of
//     mixing rounds. It must be a power of two greater than 1. Doubling it
//     doubles both time and memory.
//   - r is the block size. It scales memory and time together, and exists to
//     tune how the work maps onto a machine's memory bandwidth rather than to
//     be varied per deployment.
//   - p is the parallelism. It multiplies work *without* multiplying memory,
//     so raising p is the one knob that makes the function harder without
//     making it more memory-hard — the opposite of the point. Leave it at 1
//     unless something forces otherwise.
//
// Memory is 128·N·r bytes; MemoryBytes computes it, because the figure is
// otherwise invisible at the call site and the numbers are large. N=2²⁰ with
// r=8 is exactly one gibibyte per derivation.
//
// # Choosing values
//
// This package ships no default-parameter constants on purpose. A cost figure
// baked into a library ages into a liability, quietly reassuring callers years
// after it stopped being enough.
//
// RFC 7914 §2 gives N=16384, r=8, p=1 — 16 MiB — as its own illustration for
// interactive logins, and that is a fact about the RFC rather than a
// recommendation from here. Pick by measuring: choose the delay the
// application can afford per derivation, raise N until you reach it, and
// revisit as hardware moves. The salt must be unique per password, at least 16
// bytes from a CSPRNG, and stored alongside the derived key; it is not secret.
//
// # Which password KDF
//
// Use pbkdf2 when a specification, an interoperating implementation or FIPS
// requires it. Use argon2 for a new design with a free choice — it is the
// Password Hashing Competition winner and separates its time and memory costs
// cleanly. Use scrypt where it is already specified, which is a long list
// (Tarsnap, Ethereum keystore files, Filecoin, Litecoin, and a good number of
// disk and backup formats), or where one well-understood memory knob is
// preferable to argon2's larger parameter surface.
//
// # Implementation
//
// A thin wrapper over golang.org/x/crypto/scrypt. Key's password is a byte
// slice rather than the string that pbkdf2.Key in this module takes; that
// divergence is deliberate rather than an oversight, since a byte slice is
// what scrypt's own definition and every other implementation use. Key's
// output is a slice rather than a fixed-size array because the length is the
// caller's choice — the same exception this module's array convention makes
// for XOF output and DER.
package scrypt

import "golang.org/x/crypto/scrypt"

// Key derives keyLen bytes from password and salt under the cost parameters
// N, r and p, per RFC 7914.
//
// It returns ErrInvalidKeyLen for a non-positive key length, and the
// underlying library's own error for an invalid N, r or p — N not a power of
// two greater than one, a non-positive r or p, or parameters large enough to
// overflow (r·p must be below 2³⁰).
//
// The key-length check is this package's addition. The library underneath
// does not validate it and finishes with a PBKDF2 call that panics on the
// error the standard library returns for a non-positive length, so without
// this a zero would crash the process rather than return the error this
// signature promises.
//
// Deriving a key costs MemoryBytes(N, r) of memory and holds it for the
// duration; that is the intended behaviour, but it means a server calling
// this concurrently needs to bound how many derivations run at once. Ten
// simultaneous logins at RFC 7914's illustrative parameters is 160 MiB.
//
// The result is key material, not a password hash to be stored: it is the
// caller's job to keep the salt and parameters beside it, and to compare with
// a constant-time comparison rather than ==.
func Key(password, salt []byte, N, r, p, keyLen int) ([]byte, error) {
	if keyLen < 1 {
		return nil, ErrInvalidKeyLen
	}
	return scrypt.Key(password, salt, N, r, p, keyLen)
}

// MemoryBytes returns the memory a derivation at these parameters will use,
// 128·N·r bytes — the size of the array scrypt fills and then reads back in a
// password-dependent order, which is the whole source of its hardness.
//
// It is reported as int64 so the arithmetic cannot overflow on a 32-bit build
// for any parameters Key would accept. The figure is the one everyone quotes
// for scrypt; the working buffers alongside it add a further 256·r bytes,
// which is negligible at any N worth using.
//
// Note that p does not appear: parallelism multiplies work, not memory.
func MemoryBytes(N, r int) int64 {
	return 128 * int64(N) * int64(r)
}
