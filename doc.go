// Package cryptography is the root of a module of cryptographic
// primitives. It holds no code; the packages below it do.
//
// # Layout
//
// Every package is directly under the module root. There is no nested
// package hierarchy and no internal package, so an import path is the
// module path plus one name, and that name says what the package is:
//
//	Keys and signatures
//	    secp256k1  secp256r1  ed25519  ed448  x25519  sr25519
//	    bn254ecdsa       bls12377ecdsa       bls12381ecdsa
//	    bn254edwards     bls12377edwards     bls12381edwards
//	    bn254bls         bls12377bls         bls12381bls
//
//	Curves
//	    bn254  bls12377  bls12381
//
//	Byte hashes
//	    sha2  sha3  keccak  blake2b  blake3  md5  ripemd160
//
//	Field hashes
//	    bn254mimc        bls12377mimc        bls12381mimc
//	    bn254poseidon2   bls12377poseidon2   bls12381poseidon2
//
//	Key derivation
//	    argon2  scrypt  pbkdf2
//
//	Text encodings
//	    encoding
//
// # The curve is part of the function
//
// MiMC over BN254's scalar field and MiMC over BLS12-381's are different
// functions over different fields, with different round constants. They
// share no digests and cannot be substituted for one another. The same
// holds for ECDSA, EdDSA and BLS on each curve. So the curve is in the
// package name rather than in a parameter, and there is no way to pass the
// wrong one.
//
// # Input is a slice, output is a fixed-size array
//
// Parsing takes []byte, because that is what arrives from a wire or a
// file and its length is not known until it is checked. Everything
// produced comes back as [N]byte, or as a type wrapping one, because the
// length is a property of the function:
//
//	func Hash256(data []byte) *Digest256
//	func PublicKeyFromBytes(b []byte) (*PublicKey, error)
//	func (k *PublicKey) Bytes() [PubkeyCompressedLen]byte
//
// The exception is output whose length the caller chooses, which no type
// can carry. It is a short list, and it returns []byte: argon2.IDKey,
// argon2.IKey, scrypt.Key and pbkdf2.Key take a keyLen; sha3.HashSHAKE128,
// sha3.HashSHAKE256 and blake3.DeriveKeyN take the length directly.
//
// Streaming is the other shape with no array to return, and it uses the
// standard library's hash.Hash rather than a type of this module's. Every
// NewN does, as do blake2b.New, blake3.New and blake3.NewKeyed, whose
// digest length is a parameter.
//
// The encoding package is slice-in, slice-out throughout, since how many
// bytes a string decodes to is a property of the string. DecodeInto is
// what pairs it back with a fixed-size array, and it reports an error
// unless the input decodes to exactly the destination's length:
//
//	var k [32]byte
//	err := encoding.Hex.DecodeInto(k[:], s)
//
// # A shared method set, not an interface
//
// Every value type — PrivateKey, PublicKey, Signature, Digest — carries
// the same methods:
//
//	Bytes() [N]byte    the encoding, as a copy
//	Equal(o *T) bool   nil-safe, and constant-time where the value is secret
//	IsZero() bool      true for a nil pointer and for an uninitialised value
//	String() string    lowercase hex
//
// PrivateKey has no String: a secret should not be printable by accident.
//
// This is a convention, not a Go interface. The types differ in what Bytes
// returns — [32]byte, [33]byte, [48]byte, [64]byte — so no interface can
// describe them without erasing the length, which is the thing worth
// keeping. An interface would also let two schemes be substituted for one
// another, which is what the package split exists to prevent.
//
// Streaming accumulators are the exception, and look different because
// they are: Hasher in the field hashes has Write, Sum and Reset;
// SignatureAggregator in the BLS packages has Add, Len and Signature.
//
// # Same length is not the same type
//
// A digest carries the name of the function that produced it. SHA-256 and
// SHA-512/256 are both 32 bytes and unrelated; so are Keccak-256 and
// SHA3-256, which differ by one padding byte and are the pair an Ethereum
// address derivation gets wrong. sha2.Digest256, sha3.Digest256 and
// keccak.Digest256 are three types, so a mix-up does not compile.
//
// # File layout
//
// Inside a package: const.go holds the package doc and the lengths,
// errors.go the sentinel errors, and the rest is one file per type or per
// digest length.
//
// # Pure Go
//
// No cgo, anywhere, and no build tags selecting an assembly path this
// module wrote. It builds for any target Go supports, js/wasm included,
// and the CI builds with CGO_ENABLED=0 so a cgo dependency reappearing is
// a failure rather than a surprise.
//
// # Scope
//
// These are primitives. No package here composes one into somebody's
// identifier format, transaction layout or key derivation path: base58check
// computes the checksum but knows no version bytes, bech32 encodes a prefix
// but knows nothing about what it means, and the signature packages take a
// digest rather than a message, because which hash to use is part of the
// protocol and not of the signature.
package cryptography
