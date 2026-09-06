// Package argon2 is the public API for Argon2, the memory-hard password
// hashing function of RFC 9106 and the winner of the Password Hashing
// Competition.
//
// Argon2 is what to reach for when the choice of password KDF is free.
// Like scrypt it makes each guess cost memory rather than only CPU, and
// unlike scrypt it separates the two costs: time and memory are
// independent parameters, so a deployment can hold memory at what its
// hardware allows and tune the delay separately.
//
// # Three variants, two of them here
//
//   - Argon2id (IDKey) is the one to use. It reads memory in a
//     data-independent order for the first half-pass and a data-dependent
//     order after, which gets Argon2i's side-channel resistance where it
//     matters and Argon2d's resistance to time-memory tradeoffs
//     everywhere else. RFC 9106 §4 names it the primary recommendation.
//   - Argon2i (IKey) is fully data-independent, so its memory access
//     pattern reveals nothing about the password even to an attacker
//     watching the cache. It pays for that with weaker tradeoff
//     resistance, and needs more passes to compensate. Use it only where
//     something specifies it.
//   - Argon2d is absent. It is fully data-dependent, which makes its
//     memory access pattern a side channel on the password itself —
//     unsuitable for password hashing, which is the only thing this
//     package is for. The library underneath does not expose it either.
//
// There is deliberately no function called Key. The library underneath
// names Argon2i that, which reads like the default and is not one; code
// ported from it will fail to compile here rather than quietly derive
// under the wrong variant.
//
// # The parameters
//
//   - time is the number of passes over memory. It is the pure time knob:
//     raising it costs the defender and the attacker equally, without
//     changing the memory an attacker must buy.
//   - memory is in kibibytes, not bytes. 65536 means 64 MiB. This is the
//     parameter that does the real work — see MemoryBytes, and the note on
//     rounding below.
//   - threads is the parallelism, p in the specification: the number of
//     independent lanes the memory is split into. It multiplies work
//     without multiplying memory, and it changes the output, so it is part
//     of the parameter set to store, not a performance dial to tune per
//     machine. Its uint8 type caps it at 255, below the specification's
//     limit but far above anything useful.
//   - keyLen is the output length in bytes, caller's choice.
//
// # Memory is rounded, and the rounding is not what you store
//
// The specification computes the actual block count as
// m' = 4·p·floor(m/4·p), floored at 8·p, so a memory value that is not a
// multiple of 4·p is quietly rounded down. MemoryBytes reports what will
// really be allocated.
//
// The trap is that the *requested* m, not m', is bound into the initial
// hash. Deriving with memory=1000 and threads=4 allocates the same 992 KiB
// as memory=992 would, and produces a completely different key. So never
// "normalise" a stored parameter to its effective value: store and replay
// exactly what was passed, or the key will not reproduce.
//
// # Choosing values
//
// This package ships no default-parameter constants on purpose, for the
// same reason pbkdf2 and scrypt do not: a cost figure baked into a library
// ages into a liability.
//
// RFC 9106 §4 gives two configurations of its own, which is a fact about
// the RFC rather than a recommendation from here. Its first choice is
// time=1, memory=2097152 (2 GiB), threads=4; where that much memory is not
// available, time=3, memory=65536 (64 MiB), threads=4. Pick by measuring
// against the delay the application can afford, and bound how many
// derivations run at once — memory is the point, and ten concurrent logins
// at 64 MiB is 640 MiB.
//
// The salt must be unique per password and stored alongside the derived
// key; it is not secret. RFC 9106 requires at least 8 bytes and recommends
// 16 from a CSPRNG. That is not enforced here, matching the library
// underneath and other implementations — a short salt still derives a
// valid, reproducible key, it is simply a weaker one.
//
// # Implementation
//
// A thin wrapper over golang.org/x/crypto/argon2, whose functions return
// no error and panic on every invalid parameter. Converting those panics
// into the errors in errors.go is most of what this package does; see
// IDKey. Output is a slice rather than a fixed-size array because keyLen
// is the caller's choice — the same exception this module's convention
// makes for XOF output, and the reason there is no Digest type here.
package argon2

import "golang.org/x/crypto/argon2"

// Version is the Argon2 version these functions implement, 0x13 (19). It
// appears in the encoded hash strings other ecosystems use, as the v=19
// field; this package does not produce or parse those strings, but a
// caller building one needs the number.
const Version = argon2.Version
