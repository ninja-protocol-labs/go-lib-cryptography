package argon2

import "golang.org/x/crypto/argon2"

// IDKey derives keyLen bytes from password and salt using Argon2id — the
// variant to use unless something specifies otherwise.
//
// memory is in kibibytes and is rounded down to a multiple of 4·threads
// before allocation, while the value passed here is what gets bound into
// the derivation; see the package doc, and MemoryBytes for what will
// actually be allocated.
//
// It returns ErrInvalidTime, ErrInvalidThreads or ErrInvalidKeyLen rather
// than letting the library underneath panic on them, which is what it
// does — its own signature returns no error at all.
//
// The result is key material, not a password hash to be stored: it is the
// caller's job to keep the salt and every parameter beside it, and to
// compare with a constant-time comparison rather than ==.
func IDKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) ([]byte, error) {
	if err := checkParams(time, threads, keyLen); err != nil {
		return nil, err
	}
	return argon2.IDKey(password, salt, time, memory, threads, keyLen), nil
}

// IKey derives keyLen bytes from password and salt using Argon2i, the
// fully data-independent variant. Prefer IDKey unless something specifies
// Argon2i; this one trades tradeoff resistance for a memory access pattern
// that depends on nothing secret, and needs more passes to make up for it.
//
// Parameters and error behaviour are IDKey's.
func IKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) ([]byte, error) {
	if err := checkParams(time, threads, keyLen); err != nil {
		return nil, err
	}
	return argon2.Key(password, salt, time, memory, threads, keyLen), nil
}

// checkParams rejects everything the library underneath would panic on.
// memory is absent deliberately: no value of it panics, since the library
// clamps it into range instead.
func checkParams(time uint32, threads uint8, keyLen uint32) error {
	if time < 1 {
		return ErrInvalidTime
	}
	if threads < 1 {
		return ErrInvalidThreads
	}
	if keyLen < 1 {
		return ErrInvalidKeyLen
	}
	return nil
}

// MemoryBytes returns the memory a derivation at these parameters will
// actually allocate, in bytes.
//
// Argon2's memory parameter is a count of kibibytes, and the specification
// rounds it down to a multiple of 4·threads, then up to a floor of
// 8·threads if that left it too small. This applies both adjustments and
// converts to bytes, so what comes back is the real footprint rather than
// the number that was asked for.
//
// The unit change is deliberate: the result is bytes and the parameter is
// kibibytes, so it cannot be fed back into IDKey by accident. Doing that
// would be a bug even with the units fixed — the requested value is what
// the derivation binds, so replacing it with the effective one changes the
// key. See the package doc.
func MemoryBytes(memory uint32, threads uint8) int64 {
	const syncPoints = 4
	lanes := max(uint32(threads), 1)

	blocks := memory / (syncPoints * lanes) * (syncPoints * lanes)
	if m := 2 * syncPoints * lanes; blocks < m {
		blocks = m
	}
	return int64(blocks) * 1024
}
